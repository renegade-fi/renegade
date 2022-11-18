//! Groups the type definitions for matches

use crate::{errors::MpcError, Open};
use curve25519_dalek::scalar::Scalar;

use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigInt;

use super::{
    fee::{AuthenticatedFee, Fee},
    order::OrderSide,
};

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MatchResult {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: BigInt,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: BigInt,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: u64,
    /// The amount of the base token exchanged by this match
    pub base_amount: u64,
    /// The direction of the match, 0 implies that party 1 buys the quote and
    /// sells the base; 1 implies that party 2 buys the base and sells the quote
    pub direction: u64, // Binary
    /// The first party's fee tuple, payable to the first party's executing relayer
    pub fee1: Fee,
    /// The second party's ifee tuple, payable to the second party's executing relayer
    pub fee2: Fee,
}

impl TryFrom<&[u64]> for MatchResult {
    type Error = MpcError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        // 13 total values
        if values.len() != 13 {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 values, got {:?}",
                values.len()
            )));
        }

        Ok(MatchResult {
            quote_mint: BigInt::from(values[0]),
            base_mint: BigInt::from(values[1]),
            quote_amount: values[2],
            base_amount: values[3],
            direction: values[4],
            fee1: Fee::try_from(&values[5..9]).unwrap(),
            fee2: Fee::try_from(&values[9..]).unwrap(),
        })
    }
}

/// Represents a single match on a pair of overlapping orders
/// with values authenticated in an MPC network
#[derive(Debug, Clone)]
pub struct AuthenticatedMatchResult<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: AuthenticatedScalar<N, S>,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: AuthenticatedScalar<N, S>,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: AuthenticatedScalar<N, S>,
    /// The amount of the base token exchanged by this match
    pub base_amount: AuthenticatedScalar<N, S>,
    /// The direction of the match, 0 implies that party 1 buys the quote and
    /// sells the base; 1 implies that party 2 buys the base and sells the quote
    pub direction: AuthenticatedScalar<N, S>, // Binary
    /// The first party's fee tuple, payable to the first party's executing relayer
    pub fee1: AuthenticatedFee<N, S>,
    /// The second party's ifee tuple, payable to the second party's executing relayer
    pub fee2: AuthenticatedFee<N, S>,
}

/// Serialization to a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedMatchResult<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(match_res: AuthenticatedMatchResult<N, S>) -> Self {
        let mut res = Vec::with_capacity(3 * 4 /* 3 scalars for 4 matches */);
        res.push(match_res.quote_mint);
        res.push(match_res.base_mint);
        res.push(match_res.quote_amount);
        res.push(match_res.base_amount);
        res.push(match_res.direction);
        res.append(&mut match_res.fee1.into());
        res.append(&mut match_res.fee2.into());

        res
    }
}

/// Deserialization from a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedMatchResult<N, S>
{
    type Error = MpcError;

    fn try_from(values: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        // 13 values in the match tuple
        if values.len() != 13 {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 elements, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            quote_mint: values[0],
            quote_amount: values[1],
            base_mint: values[2],
            base_amount: values[3],
            direction: values[4],
            fee1: AuthenticatedFee::from(&values[5..9]),
            fee2: AuthenticatedFee::from(&values[9..]),
        })
    }
}

/// Implementation of opening for the single match result
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open for AuthenticatedMatchResult<N, S> {
    type OpenOutput = MatchResult;
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
