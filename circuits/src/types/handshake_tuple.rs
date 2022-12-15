//! Groups trait and type definitions for the handshake tuple

use crate::{errors::MpcError, CommitSharedProver};
use crypto::fields::bigint_to_scalar;
use curve25519_dalek::scalar::Scalar;
use itertools::Itertools;
use mpc_bulletproof::r1cs_mpc::MpcProver;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::{CryptoRng, RngCore};

use super::{
    balance::{AuthenticatedBalanceVar, AuthenticatedCommittedBalance, Balance},
    fee::{AuthenticatedCommittedFee, AuthenticatedFeeVar, Fee},
    order::{AuthenticatedCommittedOrder, AuthenticatedOrderVar, Order},
};

/// Allocate an (order, balance, fee) handshake tuple in the network for a multiprover setting
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for (Order, Balance, Fee)
{
    type SharedVarType = (
        AuthenticatedOrderVar<N, S>,
        AuthenticatedBalanceVar<N, S>,
        AuthenticatedFeeVar<N, S>,
    );
    type CommitType = (
        AuthenticatedCommittedOrder<N, S>,
        AuthenticatedCommittedBalance<N, S>,
        AuthenticatedCommittedFee<N, S>,
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
        let fee = &self.2;

        let num_committed_elements = 5 /* order */ + 2 /* balance */ + 4 /* fee */;
        let blinders = (0..num_committed_elements)
            .map(|_| Scalar::random(rng))
            .collect_vec();

        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    Scalar::from(order.quote_mint),
                    Scalar::from(order.base_mint),
                    Scalar::from(order.side as u64),
                    Scalar::from(order.price),
                    Scalar::from(order.amount),
                    Scalar::from(balance.mint),
                    Scalar::from(balance.amount),
                    bigint_to_scalar(&fee.settle_key),
                    bigint_to_scalar(&fee.gas_addr),
                    Scalar::from(fee.gas_token_amount),
                    Scalar::from(fee.percentage_fee),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let vars = (
            AuthenticatedOrderVar {
                quote_mint: shared_vars[0].to_owned(),
                base_mint: shared_vars[1].to_owned(),
                side: shared_vars[2].to_owned(),
                price: shared_vars[3].to_owned(),
                amount: shared_vars[4].to_owned(),
            },
            AuthenticatedBalanceVar {
                mint: shared_vars[5].to_owned(),
                amount: shared_vars[6].to_owned(),
            },
            AuthenticatedFeeVar {
                settle_key: shared_vars[7].to_owned(),
                gas_addr: shared_vars[8].to_owned(),
                gas_token_amount: shared_vars[9].to_owned(),
                percentage_fee: shared_vars[10].to_owned(),
            },
        );

        let comms = (
            AuthenticatedCommittedOrder {
                quote_mint: shared_comm[0].to_owned(),
                base_mint: shared_comm[1].to_owned(),
                side: shared_comm[2].to_owned(),
                price: shared_comm[3].to_owned(),
                amount: shared_comm[4].to_owned(),
            },
            AuthenticatedCommittedBalance {
                mint: shared_comm[5].to_owned(),
                amount: shared_comm[6].to_owned(),
            },
            AuthenticatedCommittedFee {
                settle_key: shared_comm[7].to_owned(),
                gas_addr: shared_comm[8].to_owned(),
                gas_token_amount: shared_comm[9].to_owned(),
                percentage_fee: shared_comm[10].to_owned(),
            },
        );

        Ok((vars, comms))
    }
}
