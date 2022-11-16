//! Groups type definitons that are useful throughout the mpc/zk circuitry
use std::borrow::Borrow;

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;

use crate::{
    errors::{MpcError, TypeConversionError},
    mpc::SharedFabric,
    Allocate, Open,
};

/**
 * Groups types definitions common to the circuit module
 */

// The depth of wallet state trees
pub const WALLET_TREE_DEPTH: usize = 8;

/// Represents a balance tuple and its analog in the constraint system
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// The mint (ERC-20 token address) of the token in the balance
    pub mint: u64,
    /// The amount of the given token stored in this balance
    pub amount: u64,
}

/// Convert a vector of u64s to a Balance
impl TryFrom<&[u64]> for Balance {
    type Error = TypeConversionError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        if values.len() != 2 {
            return Err(TypeConversionError(format!(
                "expected array of length 2, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            mint: values[0],
            amount: values[1],
        })
    }
}

impl From<&Balance> for Vec<u64> {
    fn from(balance: &Balance) -> Self {
        vec![balance.mint, balance.amount]
    }
}

/// A balance with values represented in the scalar field of the Dalek
/// Ristretto group
#[derive(Clone, Debug)]
pub struct BalanceVar {
    /// The mint (ERC-20 token address) of the token in the balance
    pub mint: Scalar,
    /// The amount of the given token stored in this balance
    pub amount: Scalar,
}

/// Convert a vector of u64s to a Balance
impl TryFrom<&[Scalar]> for BalanceVar {
    type Error = TypeConversionError;

    fn try_from(values: &[Scalar]) -> Result<Self, Self::Error> {
        if values.len() != 2 {
            return Err(TypeConversionError(format!(
                "expected array of length 2, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            mint: values[0],
            amount: values[1],
        })
    }
}

impl From<&BalanceVar> for Vec<Scalar> {
    fn from(balance: &BalanceVar) -> Self {
        vec![balance.mint, balance.amount]
    }
}

/// Represents a balance tuple that has been allocated in the network as
/// an authenticated field element
#[derive(Clone, Debug)]
pub struct AuthenticatedBalance<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 token address) of the token in the balance
    pub mint: AuthenticatedScalar<N, S>,
    /// The amount of the given token stored in this balance
    pub amount: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedBalance<N, S>
{
    type Error = MpcError;

    fn try_from(values: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        if values.len() != 2 {
            return Err(MpcError::SerializationError(format!(
                "Expected 2 values, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            mint: values[0].clone(),
            amount: values[1].clone(),
        })
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Balance {
    type Output = AuthenticatedBalance<N, S>;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::Output, MpcError> {
        let authenticated_values = fabric
            .borrow_fabric()
            .batch_allocate_private_u64s(owning_party, &[self.mint, self.amount])
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::Output {
            mint: authenticated_values[0].clone(),
            amount: authenticated_values[1].clone(),
        })
    }
}

/// Represents an order and its analog in the consraint system
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: u64,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: u64,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: OrderSide,
    /// The limit price to be executed at, in units of quote
    pub price: u64,
    /// The amount of base currency to buy or sell
    pub amount: u64,
}

/// Convert a vector of u64s to an Order
impl TryFrom<&[u64]> for Order {
    type Error = TypeConversionError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(TypeConversionError(format!(
                "expected array of length 5, got {:?}",
                value.len()
            )));
        }

        // Check that the side is 0 or 1
        if !(value[2] == 0 || value[2] == 1) {
            return Err(TypeConversionError(format!(
                "Order side must be 0 or 1, got {:?}",
                value[2]
            )));
        }

        Ok(Self {
            quote_mint: value[0],
            base_mint: value[1],
            side: if value[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
            price: value[3],
            amount: value[4],
        })
    }
}

/// Convert an order to a vector of u64s
///
/// Useful for allocating, sharing, serialization, etc
impl From<&Order> for Vec<u64> {
    fn from(o: &Order) -> Self {
        vec![o.quote_mint, o.base_mint, o.side.into(), o.price, o.amount]
    }
}

/// An order in which all the values are represented as elements of the
/// Dalek Ristretto scalar field
#[derive(Clone, Debug)]
pub struct OrderVar {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: Scalar,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: Scalar,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: Scalar,
    /// The limit price to be executed at, in units of quote
    pub price: Scalar,
    /// The amount of base currency to buy or sell
    pub amount: Scalar,
}

/// Convert a vector of u64s to an Order
impl TryFrom<&[Scalar]> for OrderVar {
    type Error = TypeConversionError;

    fn try_from(value: &[Scalar]) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(TypeConversionError(format!(
                "expected array of length 5, got {:?}",
                value.len()
            )));
        }

        // Check that the side is 0 or 1
        if !(value[2] == Scalar::zero() || value[2] == Scalar::one()) {
            return Err(TypeConversionError(format!(
                "Order side must be 0 or 1, got {:?}",
                value[2]
            )));
        }

        Ok(Self {
            quote_mint: value[0],
            base_mint: value[1],
            side: value[2],
            price: value[3],
            amount: value[4],
        })
    }
}

/// Convert an order to a vector of u64s
///
/// Useful for allocating, sharing, serialization, etc
impl From<&OrderVar> for Vec<Scalar> {
    fn from(o: &OrderVar) -> Self {
        vec![o.quote_mint, o.base_mint, o.side, o.price, o.amount]
    }
}

/// Represents an order that has been allocated in an MPC network
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedOrder<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: AuthenticatedScalar<N, S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: AuthenticatedScalar<N, S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: AuthenticatedScalar<N, S>,
    /// The limit price to be executed at, in units of quote
    pub price: AuthenticatedScalar<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: AuthenticatedScalar<N, S>,
}

/// Attempt to parse an authenticated order from a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<Vec<AuthenticatedScalar<N, S>>>
    for AuthenticatedOrder<N, S>
{
    type Error = MpcError;

    fn try_from(value: Vec<AuthenticatedScalar<N, S>>) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(MpcError::SerializationError(format!(
                "Expected 5 elements, got {}",
                value.len()
            )));
        }

        Ok(Self {
            quote_mint: value[0].clone(),
            base_mint: value[1].clone(),
            side: value[2].clone(),
            price: value[3].clone(),
            amount: value[4].clone(),
        })
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Order {
    type Output = AuthenticatedOrder<N, S>;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: crate::mpc::SharedFabric<N, S>,
    ) -> Result<Self::Output, MpcError> {
        let values_to_allocate: Vec<u64> = self.into();
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_u64s(owning_party, &values_to_allocate)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::Output::try_from(shared_values).unwrap())
    }
}

/// The side of the market a given order is on
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderSide {
    /// Buy side
    Buy = 0,
    /// Sell side
    Sell,
}

// Default for an empty order is buy
impl Default for OrderSide {
    fn default() -> Self {
        OrderSide::Buy
    }
}

impl From<OrderSide> for u64 {
    fn from(order_side: OrderSide) -> Self {
        u8::from(order_side) as u64
    }
}

impl From<OrderSide> for u8 {
    fn from(order_side: OrderSide) -> Self {
        match order_side {
            OrderSide::Buy => 0,
            OrderSide::Sell => 1,
        }
    }
}

/// Represents a fee-tuple in the state
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fee {
    /// The public settle key of the cluster collecting fees
    pub settle_key: BigUint,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: BigUint,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: u64,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: u64,
}

impl TryFrom<&[u64]> for Fee {
    type Error = TypeConversionError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        if values.len() != 4 {
            return Err(TypeConversionError(format!(
                "expected array of length 4, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            settle_key: BigUint::from(values[0]),
            gas_addr: BigUint::from(values[1]),
            gas_token_amount: values[2],
            percentage_fee: values[3],
        })
    }
}

impl From<&Fee> for Vec<u64> {
    fn from(fee: &Fee) -> Self {
        vec![
            fee.settle_key.clone().try_into().unwrap(),
            fee.gas_addr.clone().try_into().unwrap(),
            fee.gas_token_amount,
            fee.percentage_fee,
        ]
    }
}

/// A fee with values represented in the scalar field of the Dalek
/// Ristretto group
#[derive(Clone, Debug)]
pub struct FeeVar {
    /// The public settle key of the cluster collecting fees
    pub settle_key: Scalar,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: Scalar,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: Scalar,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: Scalar,
}

impl TryFrom<&[Scalar]> for FeeVar {
    type Error = TypeConversionError;

    fn try_from(values: &[Scalar]) -> Result<Self, Self::Error> {
        if values.len() != 4 {
            return Err(TypeConversionError(format!(
                "expected array of length 4, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            settle_key: values[0],
            gas_addr: values[1],
            gas_token_amount: values[2],
            percentage_fee: values[3],
        })
    }
}

impl From<&FeeVar> for Vec<Scalar> {
    fn from(fee: &FeeVar) -> Self {
        vec![
            fee.settle_key,
            fee.gas_addr,
            fee.gas_token_amount,
            fee.percentage_fee,
        ]
    }
}

/// Represents a fee tuple that has been allocated in the network as
/// an Authenticated field element
#[derive(Clone, Debug)]
pub struct AuthenticatedFee<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: AuthenticatedScalar<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: AuthenticatedScalar<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: AuthenticatedScalar<N, S>,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedFee<N, S>
{
    type Error = MpcError;

    fn try_from(values: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        if values.len() != 4 {
            return Err(MpcError::SerializationError(format!(
                "Expected 4 values, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            settle_key: values[0].clone(),
            gas_addr: values[1].clone(),
            gas_token_amount: values[2].clone(),
            percentage_fee: values[3].clone(),
        })
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<&AuthenticatedFee<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(fee: &AuthenticatedFee<N, S>) -> Self {
        vec![
            fee.settle_key.clone(),
            fee.gas_addr.clone(),
            fee.gas_token_amount.clone(),
            fee.percentage_fee.clone(),
        ]
    }
}

/// Represents a match on a single set of orders overlapping
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SingleMatchResult {
    /// Specifies the asset party 1 buys
    pub buy_side1: Match,
    /// Specifies the asset party 1 sell
    pub sell_side1: Match,
    /// Specifies the asset party 2 buys
    pub buy_side2: Match,
    /// Specifies the asset party 2 sells
    pub sell_side2: Match,
}

impl TryFrom<&[u64]> for SingleMatchResult {
    type Error = MpcError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        // 4 matches, 3 values each
        if value.len() != 3 * 4 {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 values, got {:?}",
                value.len()
            )));
        }

        Ok(SingleMatchResult {
            buy_side1: Match::try_from(&value[..3])?,
            sell_side1: Match::try_from(&value[3..6])?,
            buy_side2: Match::try_from(&value[6..9])?,
            sell_side2: Match::try_from(&value[9..])?,
        })
    }
}

/// Represents a single match on a set of overlapping orders
/// with values authenticated in an MPC network
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSingleMatchResult<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Specifies the asset party 1 buys
    pub buy_side1: AuthenticatedMatch<N, S>,
    /// Specifies the asset party 1 sell
    pub sell_side1: AuthenticatedMatch<N, S>,
    /// Specifies the asset party 2 buys
    pub buy_side2: AuthenticatedMatch<N, S>,
    /// Specifies the asset party 2 sells
    pub sell_side2: AuthenticatedMatch<N, S>,
}

/// Serialization to a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<&AuthenticatedSingleMatchResult<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(match_res: &AuthenticatedSingleMatchResult<N, S>) -> Self {
        let mut res = Vec::with_capacity(3 * 4 /* 3 scalars for 4 matches */);
        res.append(&mut match_res.buy_side1.borrow().into());
        res.append(&mut match_res.sell_side1.borrow().into());
        res.append(&mut match_res.buy_side2.borrow().into());
        res.append(&mut match_res.sell_side2.borrow().into());

        res
    }
}

/// Deserialization from a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedSingleMatchResult<N, S>
{
    type Error = MpcError;

    fn try_from(value: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        // 4 matches, 3 elements each
        if value.len() != 3 * 4 {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 elements, got {:?}",
                value.len()
            )));
        }

        Ok(Self {
            buy_side1: AuthenticatedMatch::try_from(&value[..3])?,
            sell_side1: AuthenticatedMatch::try_from(&value[3..6])?,
            buy_side2: AuthenticatedMatch::try_from(&value[8..9])?,
            sell_side2: AuthenticatedMatch::try_from(&value[9..])?,
        })
    }
}

/// Implementation of opening for the single match result
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open
    for AuthenticatedSingleMatchResult<N, S>
{
    type Output = SingleMatchResult;
    type Error = MpcError;

    fn open(&self) -> Result<Self::Output, Self::Error> {
        // Flatten the values into a shape that can be batch opened
        let flattened_self: Vec<AuthenticatedScalar<_, _>> = self.into();
        // Open the values and cast them to u64
        let opened_values = AuthenticatedScalar::batch_open(&flattened_self)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .iter()
            .map(|val| scalar_to_u64(&val.to_scalar()))
            .collect::<Vec<_>>();

        // Deserialize back into result type
        TryFrom::<&[u64]>::try_from(&opened_values)
    }

    fn open_and_authenticate(&self) -> Result<Self::Output, Self::Error> {
        // Flatten the values into a shape that can be batch opened
        let flattened_self: Vec<AuthenticatedScalar<_, _>> = self.into();
        // Open the values and cast them to u64
        let opened_values = AuthenticatedScalar::batch_open_and_authenticate(&flattened_self)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .iter()
            .map(|val| scalar_to_u64(&val.to_scalar()))
            .collect::<Vec<_>>();

        // Deserialize back into result type
        TryFrom::<&[u64]>::try_from(&opened_values)
    }
}

/// A single match which specifies the token transferred, amount, and direction of transfer
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Match {
    /// The mint (ERC-20) of the token transferred by this match
    pub mint: u64,
    /// The amount of the token transferred by this match
    pub amount: u64,
    /// The direction (buy or sell) of the transfer that this match results in
    pub side: OrderSide,
}

/// Deserialization from a list of u64s to a Match
impl TryFrom<&[u64]> for Match {
    type Error = MpcError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err(MpcError::SerializationError(format!(
                "Expected 3 elements, got {:?}",
                value.len()
            )));
        }

        if value[2] != 0 && value[2] != 1 {
            return Err(MpcError::SerializationError(format!(
                "Expected order side to be 0 or 1, got {:?}",
                value[2]
            )));
        }

        Ok(Match {
            mint: value[0],
            amount: value[1],
            side: if value[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
        })
    }
}

/// Represents a match on one side of the order that is backed by authenticated,
/// network allocated values
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMatch<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 token) that this match result swaps
    pub mint: AuthenticatedScalar<N, S>,
    /// The amount of the mint token to swap
    pub amount: AuthenticatedScalar<N, S>,
    /// The side (0 is buy, 1 is sell)
    pub side: AuthenticatedScalar<N, S>,
}

/// Serialization for opening and sending across the MPC network
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<&AuthenticatedMatch<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(val: &AuthenticatedMatch<N, S>) -> Self {
        vec![val.mint.clone(), val.amount.clone(), val.side.clone()]
    }
}

/// Deserialization from a list of shared values
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedMatch<N, S>
{
    type Error = MpcError;

    fn try_from(value: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err(MpcError::SerializationError(format!(
                "Expected 3 values, got {:?}",
                value.len()
            )));
        }

        Ok(AuthenticatedMatch {
            mint: value[0].clone(),
            amount: value[1].clone(),
            side: value[2].clone(),
        })
    }
}
