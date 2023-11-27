//! Integration tests for the settlement circuit

use bitvec::order;
use circuit_types::{balance::Balance, fixed_point::FixedPoint, order::OrderSide, wallet};
use circuits::{
    mpc_circuits::r#match::compute_match,
    test_helpers::{random_indices, random_orders_and_match},
    zk_circuits::{test_helpers::SizedWallet, valid_commitments::OrderSettlementIndices},
};
use constants::Scalar;
use eyre::Result;
use rand::{thread_rng, RngCore};
use renegade_crypto::fields::scalar_to_u64;
use test_helpers::integration_test_async;
use util::matching_engine::match_orders;

use crate::IntegrationTestArgs;

// -----------
// | Helpers |
// -----------

/// Generate two wallets with crossing orders
///
/// Returns the wallets and the indices used in the orders, as well as a
/// randomly sampled price to cross at
fn generate_wallets_for_match() -> (
    SizedWallet,
    SizedWallet,
    OrderSettlementIndices,
    OrderSettlementIndices,
    FixedPoint, // Price
) {
    let mut wallet1 = SizedWallet::default();
    let mut wallet2 = SizedWallet::default();

    // Start with the crossing orders
    let (o1, o2, price, _) = random_orders_and_match();

    // Select random indices for the orders
    let ind1 = random_indices();
    let ind2 = random_indices();

    // Add orders to the wallets
    wallet1.orders[ind1.order as usize] = o1;
    wallet2.orders[ind2.order as usize] = o2;

    // Create balances for the orders
    add_balances_to_wallet(&mut wallet1, ind1, price);
    add_balances_to_wallet(&mut wallet2, ind2, price);

    (wallet1, wallet2, ind1, ind2, price)
}

/// Add mock balances
fn add_balances_to_wallet(
    wallet: &mut SizedWallet,
    ind: OrderSettlementIndices,
    price: FixedPoint,
) {
    let mut rng = thread_rng();

    let order = &wallet.orders[ind.order as usize];
    let base_amt = order.amount;
    let quote_amt = (price * Scalar::from(base_amt)).floor();
    let quote_amt = scalar_to_u64(&quote_amt);

    let base = order.base_mint.clone();
    let quote = order.quote_mint.clone();
    let base_bal = Balance {
        mint: base.clone(),
        amount: base_amt,
    };
    let quote_bal = Balance {
        mint: quote.clone(),
        amount: quote_amt,
    };

    // Begin with a random amount of the receive side mint
    let rand_amt = rng.next_u32() as u64;
    let (send, recv) = match order.side {
        OrderSide::Buy => (
            quote_bal,
            Balance {
                mint: base,
                amount: rand_amt,
            },
        ),
        OrderSide::Sell => (
            base_bal,
            Balance {
                mint: quote,
                amount: rand_amt,
            },
        ),
    };

    // Add balances for the order
    wallet.balances[ind.send as usize] = Balance {
        mint: send_mint,
        amount: order.send_amount,
    };

    todo!()
}

// ---------
// | Tests |
// ---------

/// Tests settling a match into a set of wallet shares
///
/// Validates that the resultant shares satisfy the `VALID MATCH SETTLE`
/// circuit's constraints
async fn test_match_settle_witness_generation(test_args: IntegrationTestArgs) -> Result<()> {
    // Sample random orders and a crossing price
    let (o1, o2, price, match_res) = random_orders_and_match();

    Ok(())
}

integration_test_async!(test_match_settle_witness_generation);
