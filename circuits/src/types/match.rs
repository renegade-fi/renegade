//! Groups the type definitions for matches

use crate::{errors::MpcError, Open};
use curve25519_dalek::scalar::Scalar;

use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigInt;

/// The number of scalars in a match tuple for serialization/deserialization
const MATCH_SIZE_SCALARS: usize = 5;

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
}

impl TryFrom<&[u64]> for MatchResult {
    type Error = MpcError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        // MATCH_SIZE_SCALARS total values
        if values.len() != MATCH_SIZE_SCALARS {
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

        res
    }
}

/// Deserialization from a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedMatchResult<N, S>
{
    type Error = MpcError;

    fn try_from(values: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        // MATCH_SIZE_SCALARS values in the match tuple
        if values.len() != MATCH_SIZE_SCALARS {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 elements, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            quote_mint: values[0].clone(),
            quote_amount: values[1].clone(),
            base_mint: values[2].clone(),
            base_amount: values[3].clone(),
            direction: values[4].clone(),
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
