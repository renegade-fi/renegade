//! Groups the type definitions for matches
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use crate::{
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        LinkableBaseType, LinkableType, MpcBaseType, MpcLinearCombinationLike, MpcType,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
        MultiproverCircuitVariableType,
    },
    AuthenticatedLinkableCommitment,
};

use circuit_macros::circuit_type;
use itertools::Itertools;
use mpc_bulletproof::r1cs::{LinearCombination, Variable};
use mpc_stark::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointOpenResult, scalar::Scalar,
        stark_curve::StarkPoint,
    },
    MpcFabric,
};
use num_bigint::BigUint;
use rand::{rngs::OsRng, CryptoRng, RngCore};

/// Represents the match result of a matching MPC in the cleartext
/// in which two tokens are exchanged
/// TODO: When we convert these values to fixed point rationals, we will need to sacrifice one
/// bit of precision to ensure that the difference in prices is divisible by two
#[circuit_type(
    serde,
    singleprover_circuit,
    mpc,
    multiprover_circuit,
    multiprover_linkable,
    linkable
)]
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

    /// The minimum amount of the two orders minus the maximum amount of the two orders.
    /// We include it here to tame some of the non-linearity of the zk circuit, i.e. we
    /// can shortcut some of the computation and implicitly constrain the match result
    /// with this extra value
    pub max_minus_min_amount: u64,
    /// The index of the order (0 or 1) that has the minimum amount, i.e. the order that is
    /// completely filled by this match
    pub min_amount_order_index: u64,
}

impl AuthenticatedMatchResult {
    /// Construct a linkable type from the base, shared type
    pub fn link_commitments(self, fabric: &MpcFabric) -> AuthenticatedLinkableMatchResult {
        let mut rng = OsRng {};
        let self_serialized = self.to_authenticated_scalars();
        let randomness = (0..self_serialized.len())
            .map(|_| Scalar::random(&mut rng))
            .collect_vec();

        let authenticated_randomness = fabric.batch_allocate_preshared_scalar(randomness);

        let mut authenticated_linkable_scalars = self_serialized
            .into_iter()
            .zip(authenticated_randomness.into_iter())
            .map(|(scalar, randomness)| AuthenticatedLinkableCommitment::new(scalar, randomness))
            .flat_map(|linked_scalar| linked_scalar.to_authenticated_scalars_with_linking());

        AuthenticatedLinkableMatchResult::from_authenticated_scalars(
            &mut authenticated_linkable_scalars,
        )
    }
}
