//! Groups trait and type definitions for the handshake tuple

use crate::{
    errors::MpcError,
    zk_gadgets::fixed_point::{AuthenticatedCommittedFixedPoint, AuthenticatedFixedPointVar},
    CommitSharedProver,
};
use crypto::fields::biguint_to_scalar;
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use mpc_bulletproof::r1cs_mpc::MpcProver;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::{CryptoRng, RngCore};

use super::{
    balance::{AuthenticatedBalanceVar, AuthenticatedCommittedBalance, Balance},
    order::{AuthenticatedCommittedOrder, AuthenticatedOrderVar, Order},
};

/// Allocate an (order, balance) handshake tuple in the network for a multiprover setting
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for (Order, Balance)
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
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let order = &self.0;
        let balance = &self.1;

        let num_committed_elements = 6 /* order */ + 2 /* balance */;
        let blinders = (0..num_committed_elements)
            .map(|_| Scalar::random(rng))
            .collect_vec();

        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    biguint_to_scalar(&order.quote_mint),
                    biguint_to_scalar(&order.base_mint),
                    Scalar::from(order.side as u64),
                    Scalar::from(order.price.to_owned()),
                    Scalar::from(order.amount),
                    Scalar::from(order.timestamp),
                    biguint_to_scalar(&balance.mint),
                    Scalar::from(balance.amount),
                ],
                &blinders,
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
