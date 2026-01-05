//! Defines the intent type for the V2 darkpool

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{Amount, fixed_point::FixedPoint, traits::BaseType};
use constants::Scalar;
use serde::{Deserialize, Serialize};

#[cfg(feature = "rkyv")]
use crate::rkyv_remotes::{AddressDef, FixedPointDef};
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

#[cfg(feature = "proof-system-types")]
use {
    crate::{settlement_obligation::SettlementObligation, state_wrapper::StateWrapper},
    circuit_types::traits::{
        CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    constants::ScalarField,
    mpc_relation::{Variable, traits::Circuit},
    std::ops::Add,
};

/// An intent wrapped in a state wrapper
#[cfg(feature = "proof-system-types")]
pub type DarkpoolStateIntent = StateWrapper<Intent>;
/// An intent wrapped in a state wrapper variable
#[cfg(feature = "proof-system-types")]
pub type DarkpoolStateIntentVar = crate::state_wrapper::StateWrapperVar<Intent>;

/// Intent is a struct that represents an intent to buy or sell a token
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvDeserialize, RkyvSerialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct Intent {
    /// The token to buy
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub in_token: Address,
    /// The token to sell
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub out_token: Address,
    /// The owner of the intent, an EOA
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub owner: Address,
    /// The minimum price at which a party may settle a partial fill
    /// This is in units of `out_token/in_token`
    #[cfg_attr(feature = "rkyv", rkyv(with = FixedPointDef))]
    pub min_price: FixedPoint,
    /// The amount of the input token to trade
    pub amount_in: Amount,
}

/// A pre-match intent is an intent without the `amount_in` field
///
/// We use this type to represent intents whose `amount_in` field is determined
/// in a later circuit within a proof-linked chain of circuits. For example, we
/// may leak a `PreMatchIntentShare` in a validity circuit and separately leak
/// the `amount_in` field thereafter.
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[cfg_attr(not(feature = "proof-system-types"), circuit_type(serde))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreMatchIntent {
    /// The token to buy
    pub in_token: Address,
    /// The token to sell
    pub out_token: Address,
    /// The owner of the intent
    pub owner: Address,
    /// The minimum price at which a party may settle a partial fill
    /// This is in units of `out_token/in_token`
    pub min_price: FixedPoint,
}

impl From<Intent> for PreMatchIntent {
    fn from(intent: Intent) -> Self {
        PreMatchIntent {
            in_token: intent.in_token,
            out_token: intent.out_token,
            owner: intent.owner,
            min_price: intent.min_price,
        }
    }
}

#[cfg(feature = "proof-system-types")]
impl From<IntentShare> for PreMatchIntentShare {
    fn from(intent_share: IntentShare) -> Self {
        PreMatchIntentShare {
            in_token: intent_share.in_token,
            out_token: intent_share.out_token,
            owner: intent_share.owner,
            min_price: intent_share.min_price,
        }
    }
}

#[cfg(feature = "proof-system-types")]
impl StateWrapper<Intent> {
    /// Re-encrypt the amount in value and update the public share
    pub fn reencrypt_amount_in(&mut self) -> Scalar {
        let amount_in = self.inner.amount_in;
        let new_amount_public_share = self.stream_cipher_encrypt(&amount_in);
        self.public_share.amount_in = new_amount_public_share;
        new_amount_public_share
    }

    /// Apply a settlement obligation to the intent
    ///
    /// This just subtracts the input amount from the intent
    pub fn apply_settlement_obligation(&mut self, obligation: &SettlementObligation) {
        self.inner.amount_in -= obligation.amount_in;
        self.public_share.amount_in -= Scalar::from(obligation.amount_in);
    }
}
