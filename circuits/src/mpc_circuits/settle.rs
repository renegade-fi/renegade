//! Settles a match into secret shared wallets

use circuit_types::{
    fixed_point::{AuthenticatedFixedPoint, PROTOCOL_FEE_FP},
    r#match::{AuthenticatedFeeTake, AuthenticatedMatchResult, OrderSettlementIndices},
    wallet::AuthenticatedWalletShare,
    Fabric,
};
use constants::AuthenticatedScalar;

use crate::mpc_gadgets::{comparators::cond_select_vec, fixed_point::FixedPointMpcGadget};

/// Settles a match into two wallets and returns the updated wallet shares and
/// fee takes for each party
///
/// We settle directly into the public shares both for efficiency and to avoid
/// the need to share private shares
#[allow(clippy::too_many_arguments)]
pub fn settle_match<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    relayer_fee0: &AuthenticatedFixedPoint,
    relayer_fee1: &AuthenticatedFixedPoint,
    party0_settle_indices: OrderSettlementIndices,
    party1_settle_indices: OrderSettlementIndices,
    party0_public_share: &AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS>,
    party1_public_share: &AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS>,
    match_res: &AuthenticatedMatchResult,
    fabric: &Fabric,
) -> (
    AuthenticatedFeeTake,
    AuthenticatedFeeTake,
    AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS>,
    AuthenticatedWalletShare<MAX_BALANCES, MAX_ORDERS>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let mut party0_new_shares = party0_public_share.clone();
    let mut party1_new_shares = party1_public_share.clone();

    // Subtract the amount of base token exchanged from each party's order
    let party0_order = &mut party0_new_shares.orders[party0_settle_indices.order];
    let party1_order = &mut party1_new_shares.orders[party1_settle_indices.order];
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

    // Compute the fees paid by each party
    let (party0_fees, party1_fees) =
        compute_settlement_fees(relayer_fee0, relayer_fee1, &party0_buy, &party0_sell, fabric);

    // Update the balances of the two parties
    let party0_net = &party0_buy - party0_fees.total();
    let party0_buy_balance = &mut party0_new_shares.balances[party0_settle_indices.balance_receive];
    party0_buy_balance.amount = &party0_buy_balance.amount + &party0_net;
    party0_buy_balance.relayer_fee_balance =
        &party0_buy_balance.relayer_fee_balance + &party0_fees.relayer_fee;
    party0_buy_balance.protocol_fee_balance =
        &party0_buy_balance.protocol_fee_balance + &party0_fees.protocol_fee;

    let party1_net = &party0_sell - party1_fees.total();
    let party1_buy_balance = &mut party1_new_shares.balances[party1_settle_indices.balance_receive];
    party1_buy_balance.amount = &party1_buy_balance.amount + &party1_net;
    party1_buy_balance.relayer_fee_balance =
        &party1_buy_balance.relayer_fee_balance + &party1_fees.relayer_fee;
    party1_buy_balance.protocol_fee_balance =
        &party1_buy_balance.protocol_fee_balance + &party1_fees.protocol_fee;

    let party0_sell_balance = &mut party0_new_shares.balances[party0_settle_indices.balance_send];
    party0_sell_balance.amount = &party0_sell_balance.amount - &party0_sell;

    let party1_sell_balance = &mut party1_new_shares.balances[party1_settle_indices.balance_send];
    party1_sell_balance.amount = &party1_sell_balance.amount - &party0_buy;

    (party0_fees, party1_fees, party0_new_shares, party1_new_shares)
}

/// Compute the fee take for each party in a settlement
fn compute_settlement_fees(
    relayer_fee0: &AuthenticatedFixedPoint,
    relayer_fee1: &AuthenticatedFixedPoint,
    party0_buy_amount: &AuthenticatedScalar,
    party1_buy_amount: &AuthenticatedScalar,
    fabric: &Fabric,
) -> (AuthenticatedFeeTake, AuthenticatedFeeTake) {
    // Relayer fees
    let party0_relayer_fee_fp = relayer_fee0 * party0_buy_amount;
    let party0_relayer_fee = FixedPointMpcGadget::as_integer(&party0_relayer_fee_fp, fabric);
    let party1_relayer_fee_fp = relayer_fee1 * party1_buy_amount;
    let party1_relayer_fee = FixedPointMpcGadget::as_integer(&party1_relayer_fee_fp, fabric);

    // Protocol fees
    let protocol_fee = *PROTOCOL_FEE_FP;
    let party0_protocol_fee_fp = protocol_fee * party0_buy_amount;
    let party0_protocol_fee = FixedPointMpcGadget::as_integer(&party0_protocol_fee_fp, fabric);
    let party1_protocol_fee_fp = protocol_fee * party1_buy_amount;
    let party1_protocol_fee = FixedPointMpcGadget::as_integer(&party1_protocol_fee_fp, fabric);

    (
        AuthenticatedFeeTake { relayer_fee: party0_relayer_fee, protocol_fee: party0_protocol_fee },
        AuthenticatedFeeTake { relayer_fee: party1_relayer_fee, protocol_fee: party1_protocol_fee },
    )
}

#[cfg(test)]
mod test {
    use std::iter;

    use ark_mpc::{PARTY0, PARTY1};
    use circuit_types::{
        fixed_point::FixedPoint,
        order::OrderSide,
        r#match::{FeeTake, MatchResult, OrderSettlementIndices},
        traits::{BaseType, MpcBaseType, MpcType},
        SizedWalletShare,
    };
    use constants::Scalar;
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::scalar_to_biguint;
    use test_helpers::mpc_network::execute_mock_mpc;
    use util::matching_engine::{apply_match_to_shares, compute_fee_obligation};

    use crate::{mpc_circuits::settle::settle_match, test_helpers::random_indices};

    /// The parameterization of a test
    #[derive(Clone)]
    struct SettlementTest {
        /// The match result to settle
        match_res: MatchResult,
        /// The fee obligation of the first party
        fee_obligation0: FeeTake,
        /// The fee obligation of the second party
        fee_obligation1: FeeTake,
        /// The relayer fee for the first party
        relayer_fee0: FixedPoint,
        /// The relayer fee for the second party
        relayer_fee1: FixedPoint,
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
        let relayer_fee0 = FixedPoint::from_f64_round_down(rng.gen_range(0.0001..0.01));
        let relayer_fee1 = FixedPoint::from_f64_round_down(rng.gen_range(0.0001..0.01));
        let quote_mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let base_mint = scalar_to_biguint(&Scalar::random(&mut rng));

        let match_res = MatchResult {
            quote_mint, // Unused
            base_mint,  // Unused
            quote_amount: rng.gen(),
            base_amount: rng.gen(),
            direction: rng.gen_bool(0.5),
            min_amount_order_index: false, // Unused
        };

        let party0_pre_shares = random_shares();
        let party0_indices = random_indices();
        let party0_side = OrderSide::from(match_res.direction as u64);
        let mut party0_post_shares = party0_pre_shares.clone();
        let party0_fees = compute_fee_obligation(relayer_fee0, party0_side, &match_res);
        apply_match_to_shares(
            &mut party0_post_shares,
            &party0_indices,
            party0_fees,
            &match_res,
            party0_side,
        );

        let party1_pre_shares = random_shares();
        let party1_indices = random_indices();
        let party1_side = party0_side.opposite();
        let mut party1_post_shares = party1_pre_shares.clone();
        let party1_fees = compute_fee_obligation(relayer_fee1, party1_side, &match_res);
        apply_match_to_shares(
            &mut party1_post_shares,
            &party1_indices,
            party1_fees,
            &match_res,
            party1_side,
        );

        SettlementTest {
            match_res,
            fee_obligation0: party0_fees,
            fee_obligation1: party1_fees,
            relayer_fee0,
            relayer_fee1,
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
                let relayer_fee0 = params.relayer_fee0.allocate(PARTY0, &fabric);
                let relayer_fee1 = params.relayer_fee1.allocate(PARTY1, &fabric);
                let party0_shares = params.party0_pre_shares.allocate(PARTY1, &fabric);
                let party1_shares = params.party1_pre_shares.allocate(PARTY0, &fabric);
                let match_res = params.match_res.allocate(PARTY0, &fabric);

                let (party0_fees, party1_fees, party0_post_shares, party1_post_shares) =
                    settle_match(
                        &relayer_fee0,
                        &relayer_fee1,
                        params.party0_indices,
                        params.party1_indices,
                        &party0_shares,
                        &party1_shares,
                        &match_res,
                        &fabric,
                    );

                let party0_res = party0_post_shares.open_and_authenticate().await.unwrap();
                let party1_res = party1_post_shares.open_and_authenticate().await.unwrap();
                let party0_fees = party0_fees.open_and_authenticate().await.unwrap();
                let party1_fees = party1_fees.open_and_authenticate().await.unwrap();

                party0_res == params.party0_post_shares
                    && party1_res == params.party1_post_shares
                    && party0_fees == params.fee_obligation0
                    && party1_fees == params.fee_obligation1
            }
        })
        .await;

        assert!(res);
    }
}
