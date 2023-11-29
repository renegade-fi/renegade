//! Groups type definitions and abstractions useful in the circuitry
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(future_join)]

pub mod balance;
pub mod errors;
pub mod fee;
pub mod fixed_point;
pub mod keychain;
pub mod macro_tests;
pub mod r#match;
pub mod merkle;
pub mod order;
pub mod traits;
pub mod transfers;
pub mod wallet;

use ark_ff::BigInt;
use ark_mpc::MpcFabric;
use bigdecimal::Num;
use constants::{
    AuthenticatedScalar, Scalar, ScalarField, SystemCurve, SystemCurveGroup, MAX_BALANCES,
    MAX_FEES, MAX_ORDERS, MERKLE_HEIGHT,
};
use fixed_point::DEFAULT_FP_PRECISION;
use jf_primitives::pcs::prelude::Commitment;
use merkle::MerkleOpening;
use mpc_plonk::{
    multiprover::proof_system::{CollaborativeProof, MpcPlonkCircuit as GenericMpcPlonkCircuit},
    proof_system::structs::Proof,
};
use mpc_relation::PlonkCircuit as GenericPlonkCircuit;
use num_bigint::BigUint;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use serde::{de::Error as SerdeErr, Deserialize, Deserializer, Serialize, Serializer};
use wallet::{Wallet, WalletShare};

// -------------
// | Constants |
// -------------

/// The zero value in the Scalar field we work over
pub const SCALAR_ZERO: ScalarField = ScalarField::new(BigInt::new([0, 0, 0, 0]));
/// The one value in the Scalar field we work over
pub const SCALAR_ONE: ScalarField = ScalarField::new(BigInt::new([1, 0, 0, 0]));

/// The number of bits allowed in a balance or transaction "amount"
pub const AMOUNT_BITS: usize = 64;
/// The number of bits allowed in a price
///
/// This is the default fixed point precision plus 32 bits for the integral part
pub const PRICE_BITS: usize = DEFAULT_FP_PRECISION + 32;

/// An MPC fabric with curve generic attached
pub type Fabric = MpcFabric<SystemCurveGroup>;
/// A circuit type with curve generic attached
pub type PlonkCircuit = GenericPlonkCircuit<ScalarField>;
/// A circuit type with curve generic attached in a multiprover context
pub type MpcPlonkCircuit = GenericMpcPlonkCircuit<SystemCurveGroup>;
/// A Plonk proof represented over the system curve
pub type PlonkProof = Proof<SystemCurve>;
/// A collaborative plonk proof represented over the system curve
pub type CollaborativePlonkProof = CollaborativeProof<SystemCurve>;
/// A KZG polynomial commitment over the system curve
pub type PolynomialCommitment = Commitment<SystemCurve>;

// --------------------------
// | Default Generic Values |
// --------------------------

/// A wallet with system-wide default generic parameters attached
pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A wallet share with system-wide default generic parameters attached
pub type SizedWalletShare = WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A type alias for the Merkle opening with system-wide default generics
/// attached
pub type SizedMerkleOpening = MerkleOpening<MERKLE_HEIGHT>;

// --------------------
// | Type Definitions |
// --------------------

/// A boolean allocated in an MPC network
#[derive(Clone, Debug)]
pub struct AuthenticatedBool(AuthenticatedScalar);

/// This implementation does no validation of the underlying value, to do so
/// would require leaking privacy or otherwise complicated circuitry
///
/// The values here are eventually constrained in a collaborative proof, so
/// there is no need to validate them here
impl From<AuthenticatedScalar> for AuthenticatedBool {
    fn from(value: AuthenticatedScalar) -> Self {
        Self(value)
    }
}

impl From<AuthenticatedBool> for AuthenticatedScalar {
    fn from(value: AuthenticatedBool) -> Self {
        value.0
    }
}

// -----------
// | Helpers |
// -----------

/// Converts an element of the arkworks `ScalarField` to an `ark-mpc` type
/// `Scalar`
#[macro_export]
macro_rules! scalar {
    ($x:expr) => {
        Scalar::new($x)
    };
}

/// A helper to serialize a Scalar to a hex string
pub fn scalar_to_hex_string<S>(val: &Scalar, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    biguint_to_hex_string(&scalar_to_biguint(val), s)
}

/// A helper to deserialize a Scalar from a hex string
pub fn scalar_from_hex_string<'de, D>(d: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(biguint_to_scalar(&biguint_from_hex_string(d)?))
}

/// A helper to serialize a BigUint to a hex string
pub fn biguint_to_hex_string<S>(val: &BigUint, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&format!("0x{}", val.to_str_radix(16 /* radix */)))
}

/// A helper to deserialize a BigUint from a hex string
pub fn biguint_from_hex_string<'de, D>(d: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize as a string and remove "0x" if present
    let hex_string = String::deserialize(d)?;
    let hex_string = hex_string.strip_prefix("0x").unwrap_or(&hex_string);

    BigUint::from_str_radix(hex_string, 16 /* radix */)
        .map_err(|e| SerdeErr::custom(format!("error deserializing BigUint from hex string: {e}")))
}

/// A helper for serializing array types
pub fn serialize_array<const ARR_SIZE: usize, T, S>(
    arr: &[T; ARR_SIZE],
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + Clone,
    [(); ARR_SIZE]: Sized,
{
    // Convert the array to a vec
    let arr_vec: Vec<T> = arr.clone().into();
    arr_vec.serialize(s)
}

/// A helper for deserializing array types
pub fn deserialize_array<'de, const ARR_SIZE: usize, T, D>(d: D) -> Result<[T; ARR_SIZE], D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
    [(); ARR_SIZE]: Sized,
{
    // Deserialize a vec and then convert to an array
    let deserialized_vec: Vec<T> = Vec::deserialize(d)?;
    deserialized_vec.try_into().map_err(|_| SerdeErr::custom("incorrect size of serialized array"))
}

/// Groups helpers that operate on native types; which correspond to circuitry
/// defined in this library
pub mod native_helpers {
    use constants::Scalar;
    use itertools::Itertools;
    use renegade_crypto::hash::{compute_poseidon_hash, evaluate_hash_chain};

    use crate::{
        traits::BaseType,
        wallet::{Nullifier, Wallet, WalletShare, WalletShareStateCommitment},
    };

    /// Recover a wallet from blinded secret shares
    pub fn wallet_from_blinded_shares<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let recovered_blinder = private_shares.blinder + public_shares.blinder;
        let unblinded_public_shares = public_shares.unblind_shares(recovered_blinder);
        private_shares.clone() + unblinded_public_shares
    }

    /// Compute a commitment to the shares of a wallet
    pub fn compute_wallet_share_commitment<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> WalletShareStateCommitment
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Hash the private input, then append the public input and re-hash
        let private_input_commitment = compute_wallet_private_share_commitment(private_shares);
        let mut hash_input = vec![private_input_commitment];
        hash_input.append(&mut public_shares.to_scalars());

        compute_poseidon_hash(&hash_input)
    }

    /// Compute a commitment to a single share of a wallet
    pub fn compute_wallet_private_share_commitment<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        private_share: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Scalar
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        compute_poseidon_hash(&private_share.to_scalars())
    }

    /// Compute a commitment to the full shares of a wallet, given a commitment
    /// to only the private shares
    pub fn compute_wallet_commitment_from_private<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_share_comm: WalletShareStateCommitment,
    ) -> WalletShareStateCommitment
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let mut hash_input = vec![private_share_comm];
        hash_input.append(&mut public_shares.to_scalars());
        compute_poseidon_hash(&hash_input)
    }

    /// Compute the nullifier of a set of wallet shares
    pub fn compute_wallet_share_nullifier(
        share_commitment: WalletShareStateCommitment,
        wallet_blinder: Scalar,
    ) -> Nullifier {
        compute_poseidon_hash(&[share_commitment, wallet_blinder])
    }

    /// Reblind a wallet given its secret shares
    ///
    /// Returns the reblinded private and public shares
    pub fn reblind_wallet<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        private_secret_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Sample new wallet blinders from the `blinder` CSPRNG
        // See the comments in `valid_reblind.rs` for an explanation of the two CSPRNGs
        let mut blinder_samples = evaluate_hash_chain(
            private_secret_shares.blinder,
            2, // length
        );
        let mut blinder_drain = blinder_samples.drain(..);
        let new_blinder = blinder_drain.next().unwrap();
        let new_blinder_private_share = blinder_drain.next().unwrap();

        // Sample new secret shares for the wallet
        let shares_serialized: Vec<Scalar> = private_secret_shares.to_scalars();
        let serialized_len = shares_serialized.len();
        let mut secret_shares =
            evaluate_hash_chain(shares_serialized[serialized_len - 2], serialized_len - 1);
        secret_shares.push(new_blinder_private_share);

        create_wallet_shares_with_randomness(
            wallet,
            new_blinder,
            new_blinder_private_share,
            secret_shares,
        )
    }

    /// Construct public shares of a wallet given the private shares and blinder
    ///
    /// The return type is a tuple containing the private and public shares.
    /// Note that the private shares returned are exactly those passed in
    pub fn create_wallet_shares_from_private<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        blinder: Scalar,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Serialize the wallet's private shares and use this as the secret share stream
        let private_shares_ser: Vec<Scalar> = private_shares.clone().to_scalars();
        create_wallet_shares_with_randomness(
            wallet,
            blinder,
            private_shares.blinder,
            private_shares_ser,
        )
    }

    /// Create a secret sharing of a wallet given the secret shares and blinders
    pub fn create_wallet_shares_with_randomness<
        T,
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        blinder: Scalar,
        private_blinder_share: Scalar,
        secret_shares: T,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        T: IntoIterator<Item = Scalar>,
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let share_iter = secret_shares.into_iter();
        let wallet_scalars = wallet.to_scalars();
        let wallet_private_shares = share_iter.take(wallet_scalars.len()).collect_vec();
        let wallet_public_shares = wallet_scalars
            .iter()
            .zip_eq(wallet_private_shares.iter())
            .map(|(scalar, private_share)| scalar - private_share)
            .collect_vec();

        let mut private_shares = WalletShare::from_scalars(&mut wallet_private_shares.into_iter());
        let mut public_shares = WalletShare::from_scalars(&mut wallet_public_shares.into_iter());
        private_shares.blinder = private_blinder_share;
        public_shares.blinder = blinder - private_blinder_share;

        let blinded_public_shares = public_shares.blind_shares(blinder);

        (private_shares, blinded_public_shares)
    }
}

/// Helpers for tests
#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    use constants::SystemCurve;
    use jf_primitives::pcs::prelude::UnivariateUniversalParams;
    use lazy_static::lazy_static;
    use mpc_plonk::proof_system::{PlonkKzgSnark, UniversalSNARK};
    use rand::thread_rng;

    /// The maximum degree SRS to allocate for testing circuits
    const MAX_DEGREE_TESTING: usize = 131072;

    lazy_static! {
        /// A universal SRS for testing circuits that is generated once and used
        /// across circuits
        pub static ref TESTING_SRS: UnivariateUniversalParams<SystemCurve> = {
            let mut rng = thread_rng();
            PlonkKzgSnark::<SystemCurve>::universal_setup_for_testing(MAX_DEGREE_TESTING, &mut rng)
                .unwrap()
        };
    }
}
