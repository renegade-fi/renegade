//! Groups base and derived types for the `Balance` object
#![allow(clippy::missing_docs_in_private_items, missing_docs)]

use std::ops::Add;

use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_relation::{traits::Circuit, Variable};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    biguint_from_hex_string, biguint_to_hex_addr,
    elgamal::EncryptionKey,
    note::Note,
    r#match::FeeTake,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
        MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    validate_amount_bitlength, Amount, Fabric,
};

/// Error message when a balance amount is too large
const ERR_BALANCE_AMOUNT_TOO_LARGE: &str = "balance amount is too large";

/// Represents the base type of a balance in tuple holding a reference to the
/// ERC-20 token and its amount
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// The mint (ERC-20 token address) of the token in the balance
    #[serde(serialize_with = "biguint_to_hex_addr", deserialize_with = "biguint_from_hex_string")]
    pub mint: BigUint,
    /// The amount of the given token stored in this balance
    pub amount: Amount,
    /// The amount of this balance owed to the managing relayer cluster
    pub relayer_fee_balance: Amount,
    /// The amount of this balance owed to the protocol
    pub protocol_fee_balance: Amount,
}

impl Balance {
    /// Construct a new balance with zero fees; validating its amount
    pub fn new(mint: BigUint, amount: Amount) -> Result<Balance, String> {
        let bal = Self::new_from_mint_and_amount(mint, amount);
        bal.validate()?;

        Ok(bal)
    }

    /// Validate the balance
    pub fn validate(&self) -> Result<(), String> {
        if !validate_amount_bitlength(self.amount) {
            return Err(ERR_BALANCE_AMOUNT_TOO_LARGE.to_string());
        }

        Ok(())
    }

    /// Whether or not the instance is a default balance
    pub fn is_default(&self) -> bool {
        self.eq(&Balance::default())
    }

    /// Whether or not the balance is zero'd
    pub fn is_zero(&self) -> bool {
        self.amount == 0 && self.relayer_fee_balance == 0 && self.protocol_fee_balance == 0
    }

    /// Construct a zero'd balance from a mint
    pub fn new_from_mint(mint: BigUint) -> Balance {
        Balance { mint, amount: 0, relayer_fee_balance: 0, protocol_fee_balance: 0 }
    }

    /// Construct a balance with zero fees from a mint and amount
    pub fn new_from_mint_and_amount(mint: BigUint, amount: Amount) -> Balance {
        Balance { mint, amount, relayer_fee_balance: 0, protocol_fee_balance: 0 }
    }

    /// Get the fees due in the balance
    pub fn fees(&self) -> FeeTake {
        FeeTake { relayer_fee: self.relayer_fee_balance, protocol_fee: self.protocol_fee_balance }
    }

    /// Generate a note for the relayer fee on the balance
    ///
    /// Zeros out the relayer fee balance                   
    pub fn create_relayer_note(&mut self, relayer_key: EncryptionKey) -> Note {
        let mint = self.mint.clone();
        let amount = self.relayer_fee_balance;
        self.relayer_fee_balance = 0;

        Note::new(mint, amount, relayer_key)
    }

    /// Generate a note for the protocol fee on the balance
    ///
    /// Zeros out the protocol fee balance
    pub fn create_protocol_note(&mut self, protocol_key: EncryptionKey) -> Note {
        let mint = self.mint.clone();
        let amount = self.protocol_fee_balance;
        self.protocol_fee_balance = 0;

        Note::new(mint, amount, protocol_key)
    }
}
