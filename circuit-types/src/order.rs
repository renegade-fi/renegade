//! Groups the base type and derived types for the `Order` entity
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use constants::{AuthenticatedScalar, Scalar, ScalarField};
use mpc_relation::{traits::Circuit, BoolVar, Variable};
use num_bigint::BigUint;
use renegade_crypto::fields::scalar_to_u64;
use serde::{Deserialize, Serialize};
use std::ops::Add;

use crate::{
    biguint_from_hex_string, biguint_to_hex_string,
    fixed_point::FixedPoint,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
        MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    AuthenticatedBool, Fabric,
};

/// Represents the base type of an open order, including the asset pair, the
/// amount, price, and direction
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit, secret_share)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The mint (ERC-20 contract address) of the base token
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub base_mint: BigUint,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: OrderSide,
    /// The amount of base currency to buy or sell
    pub amount: u64,
    /// The worse case price the user is willing to accept on this order
    ///
    /// If the order is a buy, this is the maximum price the user is willing to
    /// pay If the order is a sell, this is the minimum price the user is
    /// willing to accept
    pub worst_case_price: FixedPoint,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: u64,
}

impl Order {
    /// Whether or not this is the zero'd order
    pub fn is_default(&self) -> bool {
        self.eq(&Self::default())
    }

    /// Whether or not this order is for zero volume
    ///
    /// This is a superset of the class of orders that `is_default` returns
    /// true for
    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }

    /// Determines whether the given price is within the allowable range for the
    /// order
    pub fn price_in_range(&self, price: FixedPoint) -> bool {
        match self.side {
            OrderSide::Buy => price.to_f64() <= self.worst_case_price.to_f64(),
            OrderSide::Sell => price.to_f64() >= self.worst_case_price.to_f64(),
        }
    }
}

/// The side of the market a given order is on
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    /// Buy side
    #[default]
    Buy = 0,
    /// Sell side
    Sell,
}

impl OrderSide {
    /// Return the opposite direction to self
    pub fn opposite(&self) -> OrderSide {
        match self {
            OrderSide::Buy => OrderSide::Sell,
            OrderSide::Sell => OrderSide::Buy,
        }
    }
}

impl BaseType for OrderSide {
    fn to_scalars(&self) -> Vec<Scalar> {
        vec![Scalar::from(*self as u8)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        match scalar_to_u64(&i.next().unwrap()) {
            val @ 0..=1 => OrderSide::from(val),
            x => panic!("invalid value for OrderSide({x})"),
        }
    }
}

impl CircuitBaseType for OrderSide {
    type VarType = BoolVar;
}

impl MpcBaseType for OrderSide {
    type AllocatedType = AuthenticatedBool;
}

impl SecretShareBaseType for OrderSide {
    type ShareType = Scalar;
}

impl From<OrderSide> for u64 {
    fn from(side: OrderSide) -> Self {
        match side {
            OrderSide::Buy => 0,
            OrderSide::Sell => 1,
        }
    }
}

impl From<u64> for OrderSide {
    fn from(val: u64) -> Self {
        match val {
            0 => OrderSide::Buy,
            1 => OrderSide::Sell,
            _ => panic!("invalid order side"),
        }
    }
}
