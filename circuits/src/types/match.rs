//! Groups the type definitions for matches

use crate::{errors::MpcError, CommitSharedProver, CommitVerifier, Open};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};

use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{Variable, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigInt;
use rand_core::{CryptoRng, RngCore};

/// The number of scalars in a match tuple for serialization/deserialization
pub(crate) const MATCH_SIZE_SCALARS: usize = 8;

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
/// TODO: When we convert these values to fixed point rationals, we will need to sacrifice one
/// bit of precision to ensure that the difference in prices is divisible by two
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

    /// The following are supporting variables, derivable from the above, but useful for
    /// shrinking the size of the zero knowledge circuit. As well, they are computed during
    /// the course of the MPC, so it encurs no extra cost to include them in the witness

    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: u64,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub min_minus_max_amount: u32,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: u8,
}

impl TryFrom<&[u64]> for MatchResult {
    type Error = MpcError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        // MATCH_SIZE_SCALARS total values
        if values.len() != MATCH_SIZE_SCALARS {
            return Err(MpcError::SerializationError(format!(
                "Expected {:?} values, got {:?}",
                MATCH_SIZE_SCALARS,
                values.len()
            )));
        }

        Ok(MatchResult {
            quote_mint: BigInt::from(values[0]),
            base_mint: BigInt::from(values[1]),
            quote_amount: values[2],
            base_amount: values[3],
            direction: values[4],
            execution_price: values[5],
            min_minus_max_amount: values[6] as u32,
            min_amount_order_index: values[7] as u8,
        })
    }
}

/// Represents a match result that has been allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct MatchResultVar {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: Variable,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: Variable,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: Variable,
    /// The amount of the base token exchanged by this match
    pub base_amount: Variable,
    /// The direction of the match, 0 implies that party 1 buys the quote and
    /// sells the base; 1 implies that party 2 buys the base and sells the quote
    pub direction: Variable, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: Variable,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub min_minus_max_amount: Variable,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: Variable,
}

/// A commitment to the match result in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct CommittedMatchResult {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: CompressedRistretto,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: CompressedRistretto,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: CompressedRistretto,
    /// The amount of the base token exchanged by this match
    pub base_amount: CompressedRistretto,
    /// The direction of the match, 0 implies that party 1 buys the quote and
    /// sells the base; 1 implies that party 2 buys the base and sells the quote
    pub direction: CompressedRistretto, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: CompressedRistretto,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub min_minus_max_amount: CompressedRistretto,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: CompressedRistretto,
}

impl CommitVerifier for CommittedMatchResult {
    type VarType = MatchResultVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let quote_mint_var = verifier.commit(self.quote_mint);
        let base_mint_var = verifier.commit(self.base_mint);
        let quote_amount_var = verifier.commit(self.quote_amount);
        let base_amount_var = verifier.commit(self.base_amount);
        let direction_var = verifier.commit(self.direction);
        let price_var = verifier.commit(self.execution_price);
        let min_minus_max_var = verifier.commit(self.min_minus_max_amount);
        let min_index_var = verifier.commit(self.min_amount_order_index);

        Ok(MatchResultVar {
            quote_mint: quote_mint_var,
            base_mint: base_mint_var,
            quote_amount: quote_amount_var,
            base_amount: base_amount_var,
            direction: direction_var,
            execution_price: price_var,
            min_minus_max_amount: min_minus_max_var,
            min_amount_order_index: min_index_var,
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
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: AuthenticatedScalar<N, S>,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub min_minus_max_amount: AuthenticatedScalar<N, S>,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: AuthenticatedScalar<N, S>,
}

/// Serialization to a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedMatchResult<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(match_res: AuthenticatedMatchResult<N, S>) -> Self {
        let mut res = Vec::with_capacity(MATCH_SIZE_SCALARS);
        res.push(match_res.quote_mint);
        res.push(match_res.base_mint);
        res.push(match_res.quote_amount);
        res.push(match_res.base_amount);
        res.push(match_res.direction);
        res.push(match_res.execution_price);
        res.push(match_res.min_minus_max_amount);
        res.push(match_res.min_amount_order_index);

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
                "Expected {:?} elements, got {:?}",
                MATCH_SIZE_SCALARS,
                values.len()
            )));
        }

        Ok(Self {
            quote_mint: values[0].clone(),
            quote_amount: values[1].clone(),
            base_mint: values[2].clone(),
            base_amount: values[3].clone(),
            direction: values[4].clone(),
            execution_price: values[5].clone(),
            min_minus_max_amount: values[6].clone(),
            min_amount_order_index: values[7].clone(),
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

/// Implementation of a commitment to a shared match result
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for AuthenticatedMatchResult<N, S>
{
    type SharedVarType = AuthenticatedMatchResultVar<N, S>;
    type CommitType = AuthenticatedCommittedMatchResult<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        _: u64, /* owning party unused, value is already shared */
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinders = (0..MATCH_SIZE_SCALARS)
            .map(|_| Scalar::random(rng))
            .collect_vec();
        let (commitments, vars) = prover
            .batch_commit_preshared(
                &[
                    self.quote_mint.clone(),
                    self.base_mint.clone(),
                    self.quote_amount.clone(),
                    self.base_amount.clone(),
                    self.direction.clone(),
                    self.execution_price.clone(),
                    self.min_minus_max_amount.clone(),
                    self.min_amount_order_index.clone(),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedMatchResultVar {
                quote_mint: vars[0].to_owned(),
                base_mint: vars[1].to_owned(),
                quote_amount: vars[2].to_owned(),
                base_amount: vars[3].to_owned(),
                direction: vars[4].to_owned(),
                execution_price: vars[5].to_owned(),
                min_minus_max_amount: vars[6].to_owned(),
                min_amount_order_index: vars[7].to_owned(),
            },
            AuthenticatedCommittedMatchResult {
                quote_mint: commitments[0].to_owned(),
                base_mint: commitments[1].to_owned(),
                quote_amount: commitments[2].to_owned(),
                base_amount: commitments[3].to_owned(),
                direction: commitments[4].to_owned(),
                execution_price: commitments[5].to_owned(),
                min_minus_max_amount: commitments[6].to_owned(),
                min_amount_order_index: commitments[7].to_owned(),
            },
        ))
    }
}

/// Represents a match result that has been committed to in a multi-prover constraint
/// system
#[derive(Clone, Debug)]
pub struct AuthenticatedMatchResultVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: MpcVariable<N, S>,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: MpcVariable<N, S>,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: MpcVariable<N, S>,
    /// The amount of the base token exchanged by this match
    pub base_amount: MpcVariable<N, S>,
    /// The direction of the match, 0 implies that party 1 buys the quote and
    /// sells the base; 1 implies that party 2 buys the base and sells the quote
    pub direction: MpcVariable<N, S>, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: MpcVariable<N, S>,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub min_minus_max_amount: MpcVariable<N, S>,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: MpcVariable<N, S>,
}

/// Represents a Pedersen committment to a match result in a shared constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedCommittedMatchResult<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: AuthenticatedCompressedRistretto<N, S>,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: AuthenticatedCompressedRistretto<N, S>,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: AuthenticatedCompressedRistretto<N, S>,
    /// The amount of the base token exchanged by this match
    pub base_amount: AuthenticatedCompressedRistretto<N, S>,
    /// The direction of the match, 0 implies that party 1 buys the quote and
    /// sells the base; 1 implies that party 2 buys the base and sells the quote
    pub direction: AuthenticatedCompressedRistretto<N, S>, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: AuthenticatedCompressedRistretto<N, S>,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub min_minus_max_amount: AuthenticatedCompressedRistretto<N, S>,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>
    From<AuthenticatedCommittedMatchResult<N, S>> for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    fn from(match_res: AuthenticatedCommittedMatchResult<N, S>) -> Self {
        vec![
            match_res.quote_mint,
            match_res.base_mint,
            match_res.quote_amount,
            match_res.base_amount,
            match_res.direction,
            match_res.execution_price,
            match_res.min_minus_max_amount,
            match_res.min_amount_order_index,
        ]
    }
}
