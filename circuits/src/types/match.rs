//! Groups the type definitions for matches

use crate::{
    errors::MpcError,
    zk_gadgets::fixed_point::{
        AuthenticatedCommittedFixedPoint, AuthenticatedFixedPoint, AuthenticatedFixedPointVar,
        CommittedFixedPoint, FixedPoint, FixedPointVar,
    },
    CommitProver, CommitSharedProver, CommitVerifier, Open,
};
use crypto::fields::biguint_to_scalar;
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
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// The number of scalars in a match tuple for serialization/deserialization
pub(crate) const MATCH_SIZE_SCALARS: usize = 8;

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
/// TODO: When we convert these values to fixed point rationals, we will need to sacrifice one
/// bit of precision to ensure that the difference in prices is divisible by two
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MatchResult {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: BigUint,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: BigUint,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: u64,
    /// The amount of the base token exchanged by this match
    pub base_amount: u64,
    /// The direction of the match, 0 implies that party 1 buys the base and
    /// sells the quote; 1 implies that party 2 buys the base and sells the quote
    pub direction: u64, // Binary

    /// The following are supporting variables, derivable from the above, but useful for
    /// shrinking the size of the zero knowledge circuit. As well, they are computed during
    /// the course of the MPC, so it incurs no extra cost to include them in the witness

    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: FixedPoint,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: u32,
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
            quote_mint: BigUint::from(values[0]),
            base_mint: BigUint::from(values[1]),
            quote_amount: values[2],
            base_amount: values[3],
            direction: values[4],
            execution_price: FixedPoint::from(Scalar::from(values[5])),
            max_minus_min_amount: values[6] as u32,
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
    /// The direction of the match, 0 implies that party 1 buys the base and
    /// sells the quote; 1 implies that party 2 buys the base and sells the quote
    pub direction: Variable, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: FixedPointVar,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: Variable,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: Variable,
}

/// A commitment to the match result in a single-prover constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedMatchResult {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: CompressedRistretto,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: CompressedRistretto,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: CompressedRistretto,
    /// The amount of the base token exchanged by this match
    pub base_amount: CompressedRistretto,
    /// The direction of the match, 0 implies that party 1 buys the base and
    /// sells the quote; 1 implies that party 2 buys the base and sells the quote
    pub direction: CompressedRistretto, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: CommittedFixedPoint,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: CompressedRistretto,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: CompressedRistretto,
}

impl CommitProver for MatchResult {
    type VarType = MatchResultVar;
    type CommitType = CommittedMatchResult;
    type ErrorType = ();

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut mpc_bulletproof::r1cs::Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (quote_mint_comm, quote_mint_var) =
            prover.commit(biguint_to_scalar(&self.quote_mint), Scalar::random(rng));
        let (base_mint_comm, base_mint_var) =
            prover.commit(biguint_to_scalar(&self.base_mint), Scalar::random(rng));
        let (quote_amount_comm, quote_amount_var) =
            prover.commit(Scalar::from(self.quote_amount), Scalar::random(rng));
        let (base_amount_comm, base_amount_var) =
            prover.commit(Scalar::from(self.base_amount), Scalar::random(rng));
        let (direction_comm, direction_var) =
            prover.commit(Scalar::from(self.direction), Scalar::random(rng));
        let (price_var, price_comm) = self.execution_price.commit_prover(rng, prover).unwrap();
        let (max_minus_min_comm, max_minus_min_var) =
            prover.commit(Scalar::from(self.max_minus_min_amount), Scalar::random(rng));
        let (min_index_comm, min_index_var) = prover.commit(
            Scalar::from(self.min_amount_order_index),
            Scalar::random(rng),
        );

        Ok((
            MatchResultVar {
                quote_mint: quote_mint_var,
                base_mint: base_mint_var,
                quote_amount: quote_amount_var,
                base_amount: base_amount_var,
                direction: direction_var,
                execution_price: price_var,
                max_minus_min_amount: max_minus_min_var,
                min_amount_order_index: min_index_var,
            },
            CommittedMatchResult {
                quote_mint: quote_mint_comm,
                base_mint: base_mint_comm,
                quote_amount: quote_amount_comm,
                base_amount: base_amount_comm,
                direction: direction_comm,
                execution_price: price_comm,
                max_minus_min_amount: max_minus_min_comm,
                min_amount_order_index: min_index_comm,
            },
        ))
    }
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
        let price_var = self.execution_price.commit_verifier(verifier).unwrap();
        let max_minus_min_var = verifier.commit(self.max_minus_min_amount);
        let min_index_var = verifier.commit(self.min_amount_order_index);

        Ok(MatchResultVar {
            quote_mint: quote_mint_var,
            base_mint: base_mint_var,
            quote_amount: quote_amount_var,
            base_amount: base_amount_var,
            direction: direction_var,
            execution_price: price_var,
            max_minus_min_amount: max_minus_min_var,
            min_amount_order_index: min_index_var,
        })
    }
}

/// Represents a single match on a pair of overlapping orders
/// with values authenticated in an MPC network
#[derive(Debug)]
pub struct AuthenticatedMatchResult<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint of the order token in the asset pair being matched
    pub quote_mint: AuthenticatedScalar<N, S>,
    /// The mint of the base token in the asset pair being matched
    pub base_mint: AuthenticatedScalar<N, S>,
    /// The amount of the quote token exchanged by this match
    pub quote_amount: AuthenticatedScalar<N, S>,
    /// The amount of the base token exchanged by this match
    pub base_amount: AuthenticatedScalar<N, S>,
    /// The direction of the match, 0 implies that party 1 buys the base and
    /// sells the quote; 1 implies that party 2 buys the base and sells the quote
    pub direction: AuthenticatedScalar<N, S>, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: AuthenticatedFixedPoint<N, S>,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: AuthenticatedScalar<N, S>,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: AuthenticatedScalar<N, S>,
}

/// A custom clone implementation; necessary because the MpcNetwork will not generally implement
/// clone
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedMatchResult<N, S> {
    fn clone(&self) -> Self {
        Self {
            quote_mint: self.quote_mint.clone(),
            base_mint: self.base_mint.clone(),
            quote_amount: self.quote_amount.clone(),
            base_amount: self.base_amount.clone(),
            direction: self.direction.clone(),
            execution_price: self.execution_price.clone(),
            max_minus_min_amount: self.max_minus_min_amount.clone(),
            min_amount_order_index: self.min_amount_order_index.clone(),
        }
    }
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
        res.push(match_res.execution_price.repr);
        res.push(match_res.max_minus_min_amount);
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
            execution_price: AuthenticatedFixedPoint {
                repr: values[5].clone(),
            },
            max_minus_min_amount: values[6].clone(),
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
                    self.execution_price.repr.clone(),
                    self.max_minus_min_amount.clone(),
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
                execution_price: AuthenticatedFixedPointVar {
                    repr: vars[5].to_owned().into(),
                },
                max_minus_min_amount: vars[6].to_owned(),
                min_amount_order_index: vars[7].to_owned(),
            },
            AuthenticatedCommittedMatchResult {
                quote_mint: commitments[0].to_owned(),
                base_mint: commitments[1].to_owned(),
                quote_amount: commitments[2].to_owned(),
                base_amount: commitments[3].to_owned(),
                direction: commitments[4].to_owned(),
                execution_price: AuthenticatedCommittedFixedPoint {
                    repr: commitments[5].to_owned(),
                },
                max_minus_min_amount: commitments[6].to_owned(),
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
    /// The direction of the match, 0 implies that party 1 buys the base and
    /// sells the quote; 1 implies that party 2 buys the base and sells the quote
    pub direction: MpcVariable<N, S>, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: AuthenticatedFixedPointVar<N, S>,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: MpcVariable<N, S>,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: MpcVariable<N, S>,
}

/// Represents a Pedersen commitment to a match result in a shared constraint system
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
    /// The direction of the match, 0 implies that party 1 buys the base and
    /// sells the quote; 1 implies that party 2 buys the base and sells the quote
    pub direction: AuthenticatedCompressedRistretto<N, S>, // Binary
    /// The execution price; the midpoint between two limit prices if they cross
    pub execution_price: AuthenticatedCommittedFixedPoint<N, S>,
    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: AuthenticatedCompressedRistretto<N, S>,
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
            match_res.execution_price.repr,
            match_res.max_minus_min_amount,
            match_res.min_amount_order_index,
        ]
    }
}
