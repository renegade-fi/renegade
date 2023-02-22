//! Groups trait and type definitions for the handshake tuple

use crate::{
    errors::MpcError,
    zk_gadgets::fixed_point::{AuthenticatedCommittedFixedPoint, AuthenticatedFixedPointVar},
    CommitSharedProver,
};
use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::r1cs_mpc::MpcProver;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::{CryptoRng, RngCore};

use super::{
    balance::{AuthenticatedBalanceVar, AuthenticatedCommittedBalance, LinkableBalanceCommitment},
    order::{AuthenticatedCommittedOrder, AuthenticatedOrderVar, LinkableOrderCommitment},
};

/// Allocate an (order, balance) handshake tuple in the network for a multiprover setting
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for (LinkableOrderCommitment, LinkableBalanceCommitment)
{
    type SharedVarType = (AuthenticatedOrderVar<N, S>, AuthenticatedBalanceVar<N, S>);
    type CommitType = (
        AuthenticatedCommittedOrder<N, S>,
        AuthenticatedCommittedBalance<N, S>,
    );
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        _rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let order = &self.0;
        let balance = &self.1;

        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    order.quote_mint.val,
                    order.base_mint.val,
                    order.side.val,
                    order.price.repr.val,
                    order.amount.val,
                    order.timestamp.val,
                    balance.mint.val,
                    balance.amount.val,
                ],
                &[
                    order.quote_mint.randomness,
                    order.base_mint.randomness,
                    order.side.randomness,
                    order.price.repr.randomness,
                    order.amount.randomness,
                    order.timestamp.randomness,
                    balance.mint.randomness,
                    balance.amount.randomness,
                ],
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let vars = (
            AuthenticatedOrderVar {
                quote_mint: shared_vars[0].to_owned(),
                base_mint: shared_vars[1].to_owned(),
                side: shared_vars[2].to_owned(),
                price: AuthenticatedFixedPointVar {
                    repr: shared_vars[3].to_owned().into(),
                },
                amount: shared_vars[4].to_owned(),
                timestamp: shared_vars[5].to_owned(),
            },
            AuthenticatedBalanceVar {
                mint: shared_vars[6].to_owned(),
                amount: shared_vars[7].to_owned(),
            },
        );

        let comms = (
            AuthenticatedCommittedOrder {
                quote_mint: shared_comm[0].to_owned(),
                base_mint: shared_comm[1].to_owned(),
                side: shared_comm[2].to_owned(),
                price: AuthenticatedCommittedFixedPoint {
                    repr: shared_comm[3].to_owned(),
                },
                amount: shared_comm[4].to_owned(),
                timestamp: shared_comm[5].to_owned(),
            },
            AuthenticatedCommittedBalance {
                mint: shared_comm[6].to_owned(),
                amount: shared_comm[7].to_owned(),
            },
        );

        Ok((vars, comms))
    }
}
