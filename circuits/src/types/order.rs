//! Groups the base type and derived types for the `Order` entity
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use crate::{
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        LinkableBaseType, LinkableType, MpcBaseType, MpcLinearCombinationLike, MpcType,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
        MultiproverCircuitVariableType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    types::{biguint_from_hex_string, biguint_to_hex_string},
    zk_gadgets::fixed_point::FixedPoint,
    LinkableCommitment,
};
use circuit_macros::circuit_type;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::r1cs::{LinearCombination, Variable};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Represents the base type of an open order, including the asset pair, the amount, price,
/// and direction
#[circuit_type(singleprover_circuit, mpc, multiprover_circuit, linkable, secret_share)]
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
    /// The limit price to be executed at, in units of quote per base
    pub price: FixedPoint,
    /// The amount of base currency to buy or sell
    pub amount: u64,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: u64,
}

impl Order {
    /// Whether or not this is the zero'd order
    pub fn is_default(&self) -> bool {
        self.eq(&Self::default())
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
    fn to_scalars(self) -> Vec<Scalar> {
        vec![Scalar::from(self as u8)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        match scalar_to_u64(&i.next().unwrap()) {
            val @ 0..=1 => OrderSide::from(val),
            _ => panic!("invalid value for OrderSide"),
        }
    }
}

impl CircuitBaseType for OrderSide {
    type VarType<L: LinearCombinationLike> = L;
    type CommitmentType = CompressedRistretto;

    fn commitment_randomness<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<Scalar> {
        vec![Scalar::random(rng)]
    }
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone> MpcBaseType<N, S>
    for OrderSide
{
    type AllocatedType = AuthenticatedScalar<N, S>;
}

impl<N: MpcNetwork + Send + Clone, S: SharedValueSource<Scalar> + Clone>
    MultiproverCircuitBaseType<N, S> for OrderSide
{
    type MultiproverVarType<L: MpcLinearCombinationLike<N, S>> = L;
    type MultiproverCommType = AuthenticatedCompressedRistretto<N, S>;
}

impl LinkableBaseType for OrderSide {
    type Linkable = LinkableCommitment;
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
