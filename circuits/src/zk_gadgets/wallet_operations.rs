//! Groups logic for computing wallet commitments and nullifiers inside of a
//! circuit

use circuit_types::{traits::CircuitVarType, wallet::WalletShareVar};
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use super::poseidon::PoseidonHashGadget;

// ------------------------
// | Public State Gadgets |
// ------------------------

/// A gadget for computing the commitment to a secret share of a wallet
#[derive(Clone, Debug)]
pub struct WalletShareCommitGadget<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {}
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    WalletShareCommitGadget<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// Compute the commitment to the private wallet shares
    pub fn compute_private_commitment<C: Circuit<ScalarField>>(
        private_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // Serialize the wallet and hash it into the hasher's state
        let serialized_wallet = private_wallet_share.to_vars();

        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&serialized_wallet, cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the commitment to the full wallet given a commitment to the
    /// private shares
    pub fn compute_wallet_commitment_from_private<C: Circuit<ScalarField>>(
        blinded_public_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        private_commitment: Variable,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // The public shares are added directly to a sponge H(private_commit || public
        // shares), giving the full wallet commitment
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.absorb(private_commitment, cs)?;
        hasher.batch_absorb(&blinded_public_wallet_share.to_vars(), cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the full commitment of a wallet's shares given both the public
    /// and private shares
    pub fn compute_wallet_share_commitment<C: Circuit<ScalarField>>(
        public_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        private_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // First compute the private half, then absorb in the public
        let private_comm = Self::compute_private_commitment(private_wallet_share, cs)?;
        Self::compute_wallet_commitment_from_private(public_wallet_share, private_comm, cs)
    }
}

/// A gadget for computing the nullifier of secret share to a wallet
#[derive(Clone, Debug)]
pub struct NullifierGadget {}
impl NullifierGadget {
    /// Compute the nullifier of a set of secret shares given their commitment
    pub fn wallet_shares_nullifier<C: Circuit<ScalarField>>(
        share_commitment: Variable,
        wallet_blinder: Variable,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // The nullifier is computed as H(C(w)||r)
        let mut hasher = PoseidonHashGadget::new(cs.zero());

        hasher.batch_absorb(&[share_commitment, wallet_blinder], cs)?;
        hasher.squeeze(cs)
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use circuit_types::{
        native_helpers::{
            compute_wallet_commitment_from_private, compute_wallet_private_share_commitment,
            compute_wallet_share_commitment, compute_wallet_share_nullifier,
        },
        traits::{BaseType, CircuitBaseType},
        PlonkCircuit, SizedWalletShare,
    };
    use constants::Scalar;
    use mpc_relation::traits::Circuit;
    use rand::thread_rng;

    use crate::zk_gadgets::wallet_operations::WalletShareCommitGadget;

    use super::NullifierGadget;

    /// Generate random wallet shares
    fn random_wallet_shares() -> (SizedWalletShare, SizedWalletShare) {
        let mut rng = thread_rng();
        let mut share_iter = iter::from_fn(|| Some(Scalar::random(&mut rng)));

        (
            SizedWalletShare::from_scalars(&mut share_iter),
            SizedWalletShare::from_scalars(&mut share_iter),
        )
    }

    /// Tests the wallet commitment share gadget
    #[test]
    fn test_wallet_share_commitments() {
        let (private_shares, public_shares) = random_wallet_shares();

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let private_share_var = private_shares.create_witness(&mut cs);
        let public_share_var = public_shares.create_witness(&mut cs);

        // Private share commitment
        let expected_private = compute_wallet_private_share_commitment(&private_shares);
        let expected_var = expected_private.create_public_var(&mut cs);

        let priv_comm =
            WalletShareCommitGadget::compute_private_commitment(&private_share_var, &mut cs)
                .unwrap();

        cs.enforce_equal(priv_comm, expected_var).unwrap();

        // Public share commitment
        let expected_pub = compute_wallet_commitment_from_private(&public_shares, expected_private);
        let expected_var = expected_pub.create_public_var(&mut cs);

        let pub_comm = WalletShareCommitGadget::compute_wallet_commitment_from_private(
            &public_share_var,
            priv_comm,
            &mut cs,
        )
        .unwrap();

        cs.enforce_equal(pub_comm, expected_var).unwrap();

        // Full wallet commitment
        let expected_full = compute_wallet_share_commitment(&public_shares, &private_shares);
        let expected_var = expected_full.create_public_var(&mut cs);

        let full_comm = WalletShareCommitGadget::compute_wallet_share_commitment(
            &public_share_var,
            &private_share_var,
            &mut cs,
        );

        cs.enforce_equal(full_comm.unwrap(), expected_var).unwrap();

        // Verify that all constraints are satisfied
        assert!(cs
            .check_circuit_satisfiability(&[
                expected_private.inner(),
                expected_pub.inner(),
                expected_full.inner()
            ])
            .is_ok())
    }

    /// Tests the nullifier gadget
    #[test]
    fn test_nullifier_gadget() {
        let mut rng = thread_rng();
        let share_commitment = Scalar::random(&mut rng);
        let wallet_blinder = Scalar::random(&mut rng);

        let expected = compute_wallet_share_nullifier(share_commitment, wallet_blinder);

        // Check against the gadget
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let comm_var = share_commitment.create_witness(&mut cs);
        let blinder_var = wallet_blinder.create_witness(&mut cs);

        let expected_var = expected.create_public_var(&mut cs);

        let nullifier =
            NullifierGadget::wallet_shares_nullifier(comm_var, blinder_var, &mut cs).unwrap();

        cs.enforce_equal(nullifier, expected_var).unwrap();

        // Verify that all constraints are satisfied
        assert!(cs.check_circuit_satisfiability(&[expected.inner()]).is_ok())
    }
}
