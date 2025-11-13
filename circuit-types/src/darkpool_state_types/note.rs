//! The note type, used to represent a note spent from one recipients wallet
//! into another, e.g. to transfer a fee

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
#[cfg(feature = "proof-system-types")]
use constants::EmbeddedScalarField;
use constants::{Scalar, ScalarField};
use rand::thread_rng;
use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};

use crate::Amount;
#[cfg(feature = "proof-system-types")]
use crate::elgamal::{ElGamalCiphertext, EncryptionKey};

use super::balance::Balance;

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{BaseType, CircuitBaseType, CircuitVarType},
    circuit_macros::circuit_type,
    mpc_relation::{Variable, traits::Circuit},
    renegade_crypto::fields::address_to_scalar,
};

/// The size of the note ciphertext when encrypted
///
/// We do not add the recipient to the cipher as this is unnecessary. The
/// recipient already knows their address and can check that they're able to
/// decrypt the note to know if they own it.
#[cfg(feature = "proof-system-types")]
pub const NOTE_CIPHERTEXT_SIZE: usize = Note::NUM_SCALARS - 1;

/// A note allocated into the protocol state by one user transferring to another
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// The mint of the note
    pub mint: Address,
    /// The amount of the note
    pub amount: Amount,
    /// The receiver's EOA address
    pub receiver: Address,
    /// The blinder of the note
    pub blinder: Scalar,
}

impl Note {
    /// Constructor
    pub fn new(mint: Address, amount: Amount, receiver: Address) -> Self {
        // Sample a blinder
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);

        Self { mint, amount, receiver, blinder }
    }

    /// Compute a commitment to the note
    ///
    /// The note commitment is simpler than commitments to other state elements
    /// in that we don't have secret shares to commit to. Rather, we just hash
    /// the plaintext fields of the note directly.
    #[cfg(feature = "proof-system-types")]
    pub fn commitment(&self) -> Scalar {
        let vals = self.to_scalars();
        compute_poseidon_hash(&vals)
    }

    /// Compute the nullifier for the note
    #[cfg(feature = "proof-system-types")]
    pub fn nullifier(&self) -> Scalar {
        let comm = self.commitment();
        compute_poseidon_hash(&[comm, self.blinder])
    }

    /// Get the elements of the note that are encrypted when the note is created
    #[cfg(feature = "proof-system-types")]
    pub fn plaintext_elements(&self) -> [Scalar; NOTE_CIPHERTEXT_SIZE] {
        let mint_scalar = address_to_scalar(&self.mint);
        [mint_scalar, Scalar::from(self.amount), self.blinder]
    }

    /// Encrypt the note under the given key
    ///
    /// Returns both the ciphertext and the randomness used to encrypt the note
    #[cfg(feature = "proof-system-types")]
    pub fn encrypt(
        &self,
        key: &EncryptionKey,
    ) -> (ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>, EmbeddedScalarField) {
        use crate::native_helpers::elgamal_encrypt;

        let plaintext = self.plaintext_elements();
        elgamal_encrypt::<NOTE_CIPHERTEXT_SIZE>(&plaintext, key)
    }

    /// Get the balance associated with the note
    pub fn as_balance(&self) -> Balance {
        Balance {
            mint: self.mint,
            relayer_fee_recipient: Address::ZERO,
            owner: Address::ZERO,              // Default owner
            one_time_authority: Address::ZERO, // Default one-time authority
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: self.amount,
        }
    }
}
