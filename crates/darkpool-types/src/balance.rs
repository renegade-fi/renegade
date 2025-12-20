//! Defines the balance type for the V2 darkpool

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{Amount, primitives::schnorr::SchnorrPublicKey, traits::BaseType};
use constants::Scalar;
use serde::{Deserialize, Serialize};

#[cfg(feature = "proof-system-types")]
use crate::state_wrapper::{StateWrapper, StateWrapperVar};

#[cfg(feature = "proof-system-types")]
use {
    crate::{fee::FeeTake, note::Note, settlement_obligation::SettlementObligation},
    circuit_types::traits::{
        CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType,
        SecretShareVarType,
    },
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
    rand::thread_rng,
    std::ops::Add,
};

/// A balance wrapped in a state wrapper
#[cfg(feature = "proof-system-types")]
pub type DarkpoolStateBalance = StateWrapper<Balance>;
/// A balance wrapped in a state wrapper variable
#[cfg(feature = "proof-system-types")]
pub type DarkpoolStateBalanceVar = StateWrapperVar<Balance>;

/// A balance in the V2 darkpool
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Balance {
    /// The mint of the token in the balance
    pub mint: Address,
    /// The owner of the balance
    pub owner: Address,
    /// The address to which the relayer fees are paid
    pub relayer_fee_recipient: Address,
    /// The public key which authorizes the creation of new state elements
    pub authority: SchnorrPublicKey,
    /// The relayer fee balance of the balance
    pub relayer_fee_balance: Amount,
    /// The protocol fee balance of the balance
    pub protocol_fee_balance: Amount,
    /// The amount of the token in the balance
    pub amount: Amount,
}

impl Balance {
    /// Create a new balance with zero values
    pub fn new(
        mint: Address,
        owner: Address,
        relayer_fee_recipient: Address,
        authority: SchnorrPublicKey,
    ) -> Self {
        Self {
            mint,
            owner,
            relayer_fee_recipient,
            authority,
            relayer_fee_balance: 0,
            protocol_fee_balance: 0,
            amount: 0,
        }
    }

    /// Create a new balance with the given amount
    pub fn with_amount(self, amount: Amount) -> Self {
        Self { amount, ..self }
    }
}

// Convenience helpers to update post-match fields on shares/state wrappers
#[cfg(feature = "proof-system-types")]
impl BalanceShare {
    /// Update the post-match fields on a `BalanceShare` from a
    /// `PostMatchBalanceShare`
    pub fn update_from_post_match(&mut self, post: &PostMatchBalanceShare) {
        self.amount = post.amount;
        self.relayer_fee_balance = post.relayer_fee_balance;
        self.protocol_fee_balance = post.protocol_fee_balance;
    }
}

/// A pre-match balance is a balance without the `amount` or fees fields
///
/// We use this type to represent balances whose `amount` or fees fields are
/// determined in a later circuit within a proof-linked chain of circuits. For
/// example, we may leak a `PreMatchBalanceShare` in a validity circuit and
/// separately leak the `amount` or fees fields thereafter.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreMatchBalance {
    /// The mint of the token in the balance
    pub mint: Address,
    /// The owner of the balance
    pub owner: Address,
    /// The relayer fee recipient of the balance
    pub relayer_fee_recipient: Address,
    /// The authority of the balance
    pub authority: SchnorrPublicKey,
}

/// A post-match balance splits out the `amount` and fees fields from the
/// balance
///
/// These are the values which are updated in a settlement circuit.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostMatchBalance {
    /// The relayer fee balance of the balance
    pub relayer_fee_balance: Amount,
    /// The protocol fee balance of the balance
    pub protocol_fee_balance: Amount,
    /// The amount of the token in the balance
    pub amount: Amount,
}

impl From<Balance> for PreMatchBalance {
    fn from(balance: Balance) -> Self {
        Self {
            mint: balance.mint,
            owner: balance.owner,
            relayer_fee_recipient: balance.relayer_fee_recipient,
            authority: balance.authority,
        }
    }
}

impl From<Balance> for PostMatchBalance {
    fn from(balance: Balance) -> Self {
        Self {
            amount: balance.amount,
            relayer_fee_balance: balance.relayer_fee_balance,
            protocol_fee_balance: balance.protocol_fee_balance,
        }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<BalanceShare> for PreMatchBalanceShare {
    fn from(balance_share: BalanceShare) -> Self {
        Self {
            mint: balance_share.mint,
            owner: balance_share.owner,
            relayer_fee_recipient: balance_share.relayer_fee_recipient,
            authority: balance_share.authority,
        }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<BalanceShare> for PostMatchBalanceShare {
    fn from(balance_share: BalanceShare) -> Self {
        Self {
            amount: balance_share.amount,
            relayer_fee_balance: balance_share.relayer_fee_balance,
            protocol_fee_balance: balance_share.protocol_fee_balance,
        }
    }
}

impl From<(PreMatchBalance, PostMatchBalance)> for Balance {
    fn from((pre_match_balance, post_match_balance): (PreMatchBalance, PostMatchBalance)) -> Self {
        Self {
            mint: pre_match_balance.mint,
            owner: pre_match_balance.owner,
            relayer_fee_recipient: pre_match_balance.relayer_fee_recipient,
            authority: pre_match_balance.authority,
            relayer_fee_balance: post_match_balance.relayer_fee_balance,
            protocol_fee_balance: post_match_balance.protocol_fee_balance,
            amount: post_match_balance.amount,
        }
    }
}

// ---------------------------------
// | State Wrapper Implementations |
// ---------------------------------

#[cfg(feature = "proof-system-types")]
impl StateWrapper<Balance> {
    // --- Obligation Helpers --- //

    /// Apply a settlement obligation to the balance assuming this was an input
    /// balance to a trade
    pub fn apply_obligation_in_balance(&mut self, obligation: &SettlementObligation) {
        self.inner.amount -= obligation.amount_in;
        self.public_share.amount -= Scalar::from(obligation.amount_in);
    }

    /// Apply a settlement obligation to the balance assuming this was an output
    /// balance in a trade
    ///
    /// This method does not apply the fees to the balance; use `add_fees` to do
    /// so. Rather this method subtracts the total fee from the receive amount.
    pub fn apply_obligation_out_balance_no_fees(
        &mut self,
        obligation: &SettlementObligation,
        fees: &FeeTake,
    ) {
        let receive_amt = obligation.amount_out - fees.total();
        self.inner.amount += receive_amt;
        self.public_share.amount += Scalar::from(receive_amt);
    }

    /// Apply a settlement obligation to the balance assuming this was an output
    ///
    /// This method applies the fees to the balance.
    pub fn apply_obligation_out_balance(
        &mut self,
        obligation: &SettlementObligation,
        fees: &FeeTake,
    ) {
        self.apply_obligation_out_balance_no_fees(obligation, fees);
        self.add_fees(fees);
    }

    // --- Match Share Helpers --- //

    /// Update the post-match fields on the public share from a
    /// `PostMatchBalanceShare`
    pub fn update_from_post_match(&mut self, post: &PostMatchBalanceShare) {
        self.public_share.update_from_post_match(post);
    }

    /// Re-encrypt the post match balance shares and update the public share
    pub fn reencrypt_post_match_share(&mut self) -> PostMatchBalanceShare {
        let post_match_balance = PostMatchBalance::from(self.inner.clone());
        let post_match_balance_shares = self.stream_cipher_encrypt(&post_match_balance);
        self.update_from_post_match(&post_match_balance_shares);

        post_match_balance_shares
    }

    // --- Fee Helpers --- //

    /// Apply fees to a balance
    pub fn add_fees(&mut self, fees: &FeeTake) {
        self.inner.relayer_fee_balance += fees.relayer_fee;
        self.inner.protocol_fee_balance += fees.protocol_fee;
        self.public_share.relayer_fee_balance += Scalar::from(fees.relayer_fee);
        self.public_share.protocol_fee_balance += Scalar::from(fees.protocol_fee);
    }

    /// Pay a relayer fee and generate a note
    pub fn pay_relayer_fee(&mut self) -> Note {
        // Build a note
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        let note = Note {
            mint: self.inner.mint,
            amount: self.inner.relayer_fee_balance,
            receiver: self.inner.relayer_fee_recipient,
            blinder,
        };

        // Set the relayer fee balance to zero
        self.inner.relayer_fee_balance = 0;
        self.public_share.relayer_fee_balance -= Scalar::from(note.amount);
        note
    }

    /// Re-encrypt the relayer fee share
    ///
    /// Returns the new relayer fee balance public share
    pub fn reencrypt_relayer_fee(&mut self) -> Scalar {
        let relayer_fee_balance = self.inner.relayer_fee_balance;
        let new_relayer_fee_balance_public_share = self.stream_cipher_encrypt(&relayer_fee_balance);
        self.public_share.relayer_fee_balance = new_relayer_fee_balance_public_share;
        new_relayer_fee_balance_public_share
    }

    /// Pay a protocol fee and generate a note
    pub fn pay_protocol_fee(&mut self, protocol_fee_receiver: Address) -> Note {
        let mut rng = thread_rng();
        let blinder = Scalar::random(&mut rng);
        let note = Note {
            mint: self.inner.mint,
            amount: self.inner.protocol_fee_balance,
            receiver: protocol_fee_receiver,
            blinder,
        };

        // Set the protocol fee balance to zero
        self.inner.protocol_fee_balance = 0;
        self.public_share.protocol_fee_balance -= Scalar::from(note.amount);
        note
    }

    /// Re-encrypt the protocol fee share
    ///
    /// Returns the new protocol fee balance public share
    pub fn reencrypt_protocol_fee(&mut self) -> Scalar {
        let protocol_fee_balance = self.inner.protocol_fee_balance;
        let new_protocol_fee_balance_public_share =
            self.stream_cipher_encrypt(&protocol_fee_balance);
        self.public_share.protocol_fee_balance = new_protocol_fee_balance_public_share;
        new_protocol_fee_balance_public_share
    }
}
