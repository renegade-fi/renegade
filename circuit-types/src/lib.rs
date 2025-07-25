//! Groups type definitions and abstractions useful in the circuitry
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(future_join)]

pub mod balance;
pub mod elgamal;
#[cfg(feature = "proof-system-types")]
pub mod errors;
pub mod fees;
pub mod fixed_point;
pub mod keychain;
#[cfg(feature = "proof-system-types")]
pub mod macro_tests;
pub mod r#match;
pub mod merkle;
pub mod note;
pub mod order;
#[cfg(feature = "proof-system-types")]
pub mod srs;
#[cfg(feature = "proof-system-types")]
pub mod traits;
pub mod transfers;
pub mod wallet;

use ark_ff::BigInt;
use bigdecimal::Num;
use constants::{
    ADDRESS_BYTE_LENGTH, MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT, Scalar, ScalarField,
};
use fixed_point::{DEFAULT_FP_PRECISION, FixedPoint};
use merkle::MerkleOpening;
use num_bigint::BigUint;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeErr};
use wallet::Wallet;

#[cfg(feature = "proof-system-types")]
use {
    ark_mpc::MpcFabric,
    constants::{AuthenticatedScalar, SystemCurve, SystemCurveGroup},
    jf_primitives::pcs::prelude::Commitment,
    mpc_plonk::{
        multiprover::proof_system::{
            CollaborativeProof, MpcLinkingHint, MpcPlonkCircuit as GenericMpcPlonkCircuit,
            proof_linking::MultiproverLinkingProof,
        },
        proof_system::{
            proof_linking::LinkingProof,
            structs::{LinkingHint, Proof},
        },
    },
    mpc_relation::PlonkCircuit as GenericPlonkCircuit,
    wallet::WalletShare,
};

// -------------
// | Constants |
// -------------

/// The zero value in the Scalar field we work over
pub const SCALAR_ZERO: ScalarField = ScalarField::new(BigInt::new([0, 0, 0, 0]));
/// The one value in the Scalar field we work over
pub const SCALAR_ONE: ScalarField = ScalarField::new(BigInt::new([1, 0, 0, 0]));

/// The type used to track an amount
pub type Amount = u128;
/// The number of bits allowed in a balance or transaction "amount"
pub const AMOUNT_BITS: usize = 100;
/// The number of bits allowed in a price's representation, this included the
/// fixed point precision
///
/// This is the default fixed point precision plus 32 bits for the integral part
pub const PRICE_BITS: usize = DEFAULT_FP_PRECISION + 64;
/// The number of bits allowed in a fee rate representation, including the fixed
/// point precision
///
/// Fees are naturally less than one, so we use the default fixed point
/// precision
pub const FEE_BITS: usize = DEFAULT_FP_PRECISION;

/// An MPC fabric with curve generic attached
#[cfg(feature = "proof-system-types")]
pub type Fabric = MpcFabric<SystemCurveGroup>;
/// A circuit type with curve generic attached
#[cfg(feature = "proof-system-types")]
pub type PlonkCircuit = GenericPlonkCircuit<ScalarField>;
/// A circuit type with curve generic attached in a multiprover context
#[cfg(feature = "proof-system-types")]
pub type MpcPlonkCircuit = GenericMpcPlonkCircuit<SystemCurveGroup>;
/// A Plonk proof represented over the system curve
#[cfg(feature = "proof-system-types")]
pub type PlonkProof = Proof<SystemCurve>;
/// A collaborative plonk proof represented over the system curve
#[cfg(feature = "proof-system-types")]
pub type CollaborativePlonkProof = CollaborativeProof<SystemCurve>;
/// A KZG polynomial commitment over the system curve
#[cfg(feature = "proof-system-types")]
pub type PolynomialCommitment = Commitment<SystemCurve>;
/// A proof linking hint defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type ProofLinkingHint = LinkingHint<SystemCurve>;
/// A collaboratively generated proof linking hint defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type MpcProofLinkingHint = MpcLinkingHint<SystemCurve>;
/// A linking proof defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type PlonkLinkProof = LinkingProof<SystemCurve>;
/// A collaboratively generated linking proof defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type MpcPlonkLinkProof = MultiproverLinkingProof<SystemCurve>;

// --------------------------
// | Default Generic Values |
// --------------------------

/// A wallet with system-wide default generic parameters attached
pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS>;
/// A wallet share with system-wide default generic parameters attached
#[cfg(feature = "proof-system-types")]
pub type SizedWalletShare = WalletShare<MAX_BALANCES, MAX_ORDERS>;
/// A type alias for the Merkle opening with system-wide default generics
/// attached
pub type SizedMerkleOpening = MerkleOpening<MERKLE_HEIGHT>;

// --------------------
// | Type Definitions |
// --------------------

/// A boolean allocated in an MPC network
#[cfg(feature = "proof-system-types")]
#[derive(Clone, Debug)]
pub struct AuthenticatedBool(AuthenticatedScalar);

/// This implementation does no validation of the underlying value, to do so
/// would require leaking privacy or otherwise complicated circuitry
///
/// The values here are eventually constrained in a collaborative proof, so
/// there is no need to validate them here
#[cfg(feature = "proof-system-types")]
impl From<AuthenticatedScalar> for AuthenticatedBool {
    fn from(value: AuthenticatedScalar) -> Self {
        Self(value)
    }
}

#[cfg(feature = "proof-system-types")]
impl From<AuthenticatedBool> for AuthenticatedScalar {
    fn from(value: AuthenticatedBool) -> Self {
        value.0
    }
}

/// A type alias for an on-chain address, we represent these as `BigUint`
pub type Address = BigUint;

// -----------
// | Helpers |
// -----------

/// Get the maximum representable price
pub fn max_price() -> FixedPoint {
    let repr_bigint = (BigUint::from(1u8) << PRICE_BITS) - 1u8;
    let repr = biguint_to_scalar(&repr_bigint);
    FixedPoint::from_repr(repr)
}

/// Get the maximum representable amount
pub fn max_amount() -> Amount {
    (1u128 << AMOUNT_BITS) - 1
}

/// Verify that an amount is within the correct bitlength
pub fn validate_amount_bitlength(amount: Amount) -> bool {
    let max_amount = (1u128 << AMOUNT_BITS) - 1;
    amount <= max_amount
}

/// Verify that a price is within the correct bitlength
pub fn validate_price_bitlength(price: FixedPoint) -> bool {
    let max_repr = (1u128 << PRICE_BITS) - 1;
    price.repr <= Scalar::from(max_repr)
}

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

/// A helper to serialize a BigUint to a hex address
pub fn biguint_to_hex_addr<S>(val: &BigUint, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut bytes = [0_u8; ADDRESS_BYTE_LENGTH];
    let val_bytes = val.to_bytes_be();

    let len = val_bytes.len();
    debug_assert!(len <= ADDRESS_BYTE_LENGTH, "BigUint too large for an address");

    bytes[ADDRESS_BYTE_LENGTH - val_bytes.len()..].copy_from_slice(&val_bytes);
    let hex_str = hex::encode(bytes);

    s.serialize_str(&format!("0x{hex_str}"))
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
#[cfg(feature = "proof-system-types")]
pub mod native_helpers {
    use ark_ff::UniformRand;
    use constants::{EmbeddedScalarField, Scalar};
    use itertools::Itertools;
    use jf_primitives::elgamal::{DecKey, EncKey};
    use rand::thread_rng;
    use renegade_crypto::hash::{compute_poseidon_hash, evaluate_hash_chain};

    use crate::{
        elgamal::{DecryptionKey, ElGamalCiphertext, EncryptionKey},
        note::{NOTE_CIPHERTEXT_SIZE, Note},
        traits::{BaseType, CircuitBaseType},
        wallet::{Nullifier, Wallet, WalletShare, WalletShareStateCommitment},
    };

    // -----------------
    // | Wallet Shares |
    // -----------------

    /// Recover a wallet from blinded secret shares
    pub fn wallet_from_blinded_shares<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> Wallet<MAX_BALANCES, MAX_ORDERS> {
        let recovered_blinder = private_shares.blinder + public_shares.blinder;
        let unblinded_public_shares = public_shares.unblind_shares(recovered_blinder);
        private_shares.clone() + unblinded_public_shares
    }

    /// Compute a commitment to the shares of a wallet
    pub fn compute_wallet_share_commitment<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> WalletShareStateCommitment {
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
    >(
        private_share: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> Scalar {
        compute_poseidon_hash(&private_share.to_scalars())
    }

    /// Compute a commitment to the full shares of a wallet, given a commitment
    /// to only the private shares
    pub fn compute_wallet_commitment_from_private<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        private_share_comm: WalletShareStateCommitment,
    ) -> WalletShareStateCommitment {
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
    pub fn reblind_wallet<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        private_secret_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>) {
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
    pub fn create_wallet_shares_from_private<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        blinder: Scalar,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>) {
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
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        blinder: Scalar,
        private_blinder_share: Scalar,
        secret_shares: T,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>)
    where
        T: IntoIterator<Item = Scalar>,
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

    // -------------------
    // | Note Operations |
    // -------------------

    /// Encrypt a note under the given key, returning both the ciphertext and
    /// the randomness
    pub fn encrypt_note(
        note: &Note,
        key: &EncryptionKey,
    ) -> (ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>, EmbeddedScalarField) {
        let plaintext = note.plaintext_elements();
        elgamal_encrypt::<NOTE_CIPHERTEXT_SIZE>(&plaintext, key)
    }

    /// Compute a commitment to a note
    pub fn note_commitment(note: &Note) -> Scalar {
        compute_poseidon_hash(&note.to_scalars())
    }

    /// Compute the nullifier for a note
    pub fn note_nullifier(note_comm: Scalar, note_blinder: Scalar) -> Scalar {
        compute_poseidon_hash(&[note_comm, note_blinder])
    }

    // -------------------------
    // | Cryptographic Helpers |
    // -------------------------

    /// Encrypt a plaintext buffer under the given key, returning both the
    /// ciphertext and the randomness used to encrypt
    pub fn elgamal_encrypt<const N: usize>(
        plaintext: &[Scalar],
        key: &EncryptionKey,
    ) -> (ElGamalCiphertext<N>, EmbeddedScalarField) {
        let mut rng = thread_rng();
        let randomness = EmbeddedScalarField::rand(&mut rng);

        let jf_key = EncKey::from(*key);
        let jf_plaintext = plaintext.iter().map(Scalar::inner).collect_vec();
        let cipher = jf_key.deterministic_encrypt(randomness, &jf_plaintext);

        (cipher.into(), randomness)
    }

    /// Decrypt a ciphertext under the given key
    pub fn elgamal_decrypt<const N: usize, T: CircuitBaseType>(
        ciphertext: &ElGamalCiphertext<N>,
        key: &DecryptionKey,
    ) -> T {
        let jf_key = DecKey::from(*key);
        let jf_cipher = ciphertext.clone().into();
        let mut plaintext_iter = jf_key.decrypt(&jf_cipher).into_iter().map(Scalar::new);

        T::from_scalars(&mut plaintext_iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_price_validation() {
        // Valid price
        let valid_price = FixedPoint::from_f64_round_down(1234.5678);
        assert!(validate_price_bitlength(valid_price));

        // Maximum representable price
        let repr = Scalar::from(1u8).pow(PRICE_BITS as u64) - Scalar::one();
        let max_price = FixedPoint::from_repr(repr);
        assert!(validate_price_bitlength(max_price));

        // Minimum non-representable price
        let repr = repr + Scalar::one();
        let min_price = FixedPoint::from_repr(repr);
        assert!(validate_price_bitlength(min_price));

        // Invalid price (too large)
        let invalid_price = FixedPoint::from_f64_round_down(1e200); // Assuming this is larger than 2^PRICE_BITS
        assert!(!validate_price_bitlength(invalid_price));
    }

    #[test]
    fn test_amount_validation() {
        // Valid amount
        let valid_amount = 1_000_000;
        assert!(validate_amount_bitlength(valid_amount));

        // Maximum representable amount
        let max_amount = (1u128 << AMOUNT_BITS) - 1;
        assert!(validate_amount_bitlength(max_amount));

        // Minimum non-representable amount
        let min_amount = 1;
        assert!(validate_amount_bitlength(min_amount));

        // Invalid amount (too large)
        let invalid_amount = u128::MAX;
        assert!(!validate_amount_bitlength(invalid_amount));
    }
}
