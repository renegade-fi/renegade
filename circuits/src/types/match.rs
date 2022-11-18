//! Groups the type definitions for matches

use crate::{errors::MpcError, Open};
use curve25519_dalek::scalar::Scalar;

use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};

use super::order::OrderSide;

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
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedSingleMatchResult<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(match_res: AuthenticatedSingleMatchResult<N, S>) -> Self {
        let mut res = Vec::with_capacity(3 * 4 /* 3 scalars for 4 matches */);
        res.append(&mut match_res.buy_side1.into());
        res.append(&mut match_res.sell_side1.into());
        res.append(&mut match_res.buy_side2.into());
        res.append(&mut match_res.sell_side2.into());

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
    type OpenOutput = SingleMatchResult;
    type Error = MpcError;

    fn open(self) -> Result<Self::OpenOutput, Self::Error> {
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

    fn open_and_authenticate(self) -> Result<Self::OpenOutput, Self::Error> {
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
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedMatch<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(val: AuthenticatedMatch<N, S>) -> Self {
        vec![val.mint, val.amount, val.side]
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
