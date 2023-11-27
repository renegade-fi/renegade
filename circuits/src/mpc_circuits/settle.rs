//! Settles a match into secret shared wallets

use circuit_types::{r#match::AuthenticatedMatchResult, wallet::AuthenticatedWalletShare};

use crate::{
    mpc_gadgets::comparators::cond_select_vec,
    zk_circuits::valid_commitments::OrderSettlementIndices,
};

/// Settles a match into two wallets and returns the updated wallet shares
///
/// We settle directly into the public shares both for efficiency and to avoid
/// the need to share private shares
pub fn settle_match<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>(
    party0_settle_indices: OrderSettlementIndices,
    party1_settle_indices: OrderSettlementIndices,
    party0_public_share: &AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    party1_public_share: &AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    match_res: &AuthenticatedMatchResult,
) -> (
    AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let mut party0_new_shares = party0_public_share.clone();
    let mut party1_new_shares = party1_public_share.clone();

    // Subtract the amount of base token exchanged from each party's order
    let party0_order = &mut party0_new_shares.orders[party0_settle_indices.order as usize];
    let party1_order = &mut party1_new_shares.orders[party1_settle_indices.order as usize];
    party0_order.amount = &party0_order.amount - &match_res.base_amount;
    party1_order.amount = &party1_order.amount - &match_res.base_amount;

    // Select the correct ordering of the two mints for buy and sell side
    let mut amounts = cond_select_vec(
        &match_res.direction,
        &[match_res.quote_amount.clone(), match_res.base_amount.clone()],
        &[match_res.base_amount.clone(), match_res.quote_amount.clone()],
    );

    let party0_buy = amounts.remove(0);
    let party0_sell = amounts.remove(0);

    // Update the balances of the two parties
    let party0_buy_balance =
        &mut party0_new_shares.balances[party0_settle_indices.balance_receive as usize];
    party0_buy_balance.amount = &party0_buy_balance.amount + &party0_buy;

    let party1_buy_balance =
        &mut party1_new_shares.balances[party1_settle_indices.balance_receive as usize];
    party1_buy_balance.amount = &party1_buy_balance.amount + &party0_sell;

    let party0_sell_balance =
        &mut party0_new_shares.balances[party0_settle_indices.balance_send as usize];
    party0_sell_balance.amount = &party0_sell_balance.amount - &party0_sell;

    let party1_sell_balance =
        &mut party1_new_shares.balances[party1_settle_indices.balance_send as usize];
    party1_sell_balance.amount = &party1_sell_balance.amount - &party0_buy;

    (party0_new_shares, party1_new_shares)
}

#[cfg(test)]
mod test {
    use std::iter;

    use ark_mpc::{PARTY0, PARTY1};
    use circuit_types::{
        order::OrderSide,
        r#match::MatchResult,
        traits::{BaseType, MpcBaseType, MpcType},
        SizedWalletShare,
    };
    use constants::Scalar;
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::scalar_to_biguint;
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        mpc_circuits::settle::settle_match,
        test_helpers::random_indices,
        zk_circuits::{
            valid_commitments::OrderSettlementIndices,
            valid_match_settle::test_helpers::apply_match_to_shares,
        },
    };

    /// The parameterization of a test
    #[derive(Clone)]
    struct SettlementTest {
        /// The match result to settle
        match_res: MatchResult,
        /// The shares of the first party before settlement
        party0_pre_shares: SizedWalletShare,
        /// The indices of the first party's order and balances to settle
        party0_indices: OrderSettlementIndices,
        /// The shares of the second party before settlement
        party1_pre_shares: SizedWalletShare,
        /// The indices of the second party's order and balances to settle
        party1_indices: OrderSettlementIndices,
        /// The shares of the first party after settlement
        party0_post_shares: SizedWalletShare,
        /// The shares of the second party after settlement
        party1_post_shares: SizedWalletShare,
    }

    /// Get a dummy set of inputs for a settlement circuit
    fn generate_test_params() -> SettlementTest {
        let mut rng = thread_rng();
        let quote_mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let base_mint = scalar_to_biguint(&Scalar::random(&mut rng));

        let match_res = MatchResult {
            quote_mint, // Unused
            base_mint,  // Unused
            quote_amount: rng.gen(),
            base_amount: rng.gen(),
            direction: rng.gen_bool(0.5),
            max_minus_min_amount: 0,       // Unused
            min_amount_order_index: false, // Unused
        };

        let party0_pre_shares = random_shares();
        let party0_indices = random_indices();
        let party0_side = OrderSide::from(match_res.direction as u64);
        let party0_post_shares =
            apply_match_to_shares(&party0_pre_shares, &party0_indices, &match_res, party0_side);

        let party1_pre_shares = random_shares();
        let party1_indices = random_indices();
        let party1_side = party0_side.opposite();
        let party1_post_shares =
            apply_match_to_shares(&party1_pre_shares, &party1_indices, &match_res, party1_side);

        SettlementTest {
            match_res,
            party0_pre_shares,
            party0_indices,
            party0_post_shares,
            party1_pre_shares,
            party1_indices,
            party1_post_shares,
        }
    }

    /// Generate a random set of wallet shares
    fn random_shares() -> SizedWalletShare {
        let mut rng = thread_rng();
        SizedWalletShare::from_scalars(&mut iter::from_fn(|| Some(Scalar::random(&mut rng))))
    }

    /// Tests settlement of a match into two wallets
    #[tokio::test]
    async fn test_settle() {
        // Generate a randomized test
        let params = generate_test_params();

        let (res, _) = execute_mock_mpc(move |fabric| {
            let params = params.clone();

            async move {
                let party0_shares = params.party0_pre_shares.allocate(PARTY1, &fabric);
                let party1_shares = params.party1_pre_shares.allocate(PARTY0, &fabric);
                let match_res = params.match_res.allocate(PARTY0, &fabric);

                let (party0_post_shares, party1_post_shares) = settle_match(
                    params.party0_indices,
                    params.party1_indices,
                    &party0_shares,
                    &party1_shares,
                    &match_res,
                );

                let party0_res = party0_post_shares.open_and_authenticate().await.unwrap();
                let party1_res = party1_post_shares.open_and_authenticate().await.unwrap();

                party0_res == params.party0_post_shares && party1_res == params.party1_post_shares
            }
        })
        .await;

        assert!(res);
    }
}
