//! The note type, used to represent a note spent from one recipients wallet
//! into another, e.g. to transfer a fee

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use constants::{Scalar, ScalarField};
use mpc_relation::{traits::Circuit, Variable};
use rand::thread_rng;
use renegade_crypto::{fields::biguint_to_scalar, hash::compute_poseidon_hash};
use serde::{Deserialize, Serialize};

use crate::{
    balance::Balance,
    elgamal::EncryptionKey,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    Address, Amount,
};

/// The size of the note ciphertext when encrypted
///
/// We do not add the recipient to the cipher as this is the key encrypted
/// under, so the size is the number of scalars excluding the recipient
pub const NOTE_CIPHERTEXT_SIZE: usize = Note::NUM_SCALARS - EncryptionKey::NUM_SCALARS;

/// A note allocated into the protocol state by one user transferring to another
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// The mint of the note
    pub mint: Address,
    /// The amount of the note
    pub amount: Amount,
    /// The receiver's identification key
    pub receiver: EncryptionKey,
    /// The blinder of the note
    pub blinder: Scalar,
}

impl Note {
    /// Constructor
    pub fn new(mint: Address, amount: Amount, receiver: EncryptionKey) -> Self {
        // Sample a blinder
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);

        Note { mint, amount, receiver, blinder }
    }

    /// Compute a commitment to the note
    pub fn commitment(&self) -> Scalar {
        let vals = self.to_scalars();
        compute_poseidon_hash(&vals)
    }

    /// Compute the nullifier for the note
    pub fn nullifier(&self) -> Scalar {
        let comm = self.commitment();
        compute_poseidon_hash(&[comm, self.blinder])
    }

    /// Get the elements of the note that are encrypted when the note is created
    pub fn plaintext_elements(&self) -> [Scalar; NOTE_CIPHERTEXT_SIZE] {
        [biguint_to_scalar(&self.mint), Scalar::from(self.amount), self.blinder]
    }

    /// Get the balance associated with the note
    pub fn as_balance(&self) -> Balance {
        Balance::new_from_mint_and_amount(self.mint.clone(), self.amount)
    }
}
