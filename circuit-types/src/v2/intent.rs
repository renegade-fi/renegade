//! Defines the intent type for the V2 darkpool

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use crate::{
    Amount,
    fixed_point::FixedPoint,
    state_wrapper::{StateWrapper, StateWrapperVar},
};

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{
        BaseType, CircuitBaseType, CircuitVarType, SecretShareBaseType, SecretShareType,
        SecretShareVarType,
    },
    circuit_macros::circuit_type,
    constants::{Scalar, ScalarField},
    mpc_relation::{Variable, traits::Circuit},
};

/// An intent wrapped in a state wrapper
pub type DarkpoolStateIntent = StateWrapper<Intent>;
/// An intent wrapped in a state wrapper variable
pub type DarkpoolStateIntentVar = StateWrapperVar<Intent>;

/// Intent is a struct that represents an intent to buy or sell a token
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit, secret_share))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    /// The token to buy
    pub in_token: Address,
    /// The token to sell
    pub out_token: Address,
    /// The owner of the intent, an EOA
    pub owner: Address,
    /// The minimum price at which a party may settle a partial fill
    /// This is in units of `out_token/in_token`
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
