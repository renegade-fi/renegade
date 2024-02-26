//! Tests for matching orders via an MPC

use ark_mpc::{PARTY0, PARTY1};
use circuit_types::{
    balance::Balance,
    fee::Fee,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
};
use common::types::{wallet::Wallet, wallet_mocks::mock_empty_wallet};
use eyre::Result;
use job_types::handshake_manager::HandshakeExecutionJob;
use num_bigint::BigUint;
use test_helpers::integration_test_async;
use util::hex::biguint_from_hex_string;
use uuid::Uuid;

use crate::{helpers::allocate_wallet, IntegrationTestArgs, MOCK_EXECUTION_PRICE};

/// The address of the mock quote mint
const QUOTE_MINT_ADDR: &str = "0x1";
/// The address of the mock base mint
const BASE_MINT_ADDR: &str = "0x2";

/// The ID that the first party assigns their order
const ORDER_ID1: &str = "5e4216d2-dc68-431f-a8c6-098d672ea88e";
/// The ID that the second party assigns their order
const ORDER_ID2: &str = "c43f47f3-e944-4857-b52f-1e2e889e7c3e";

/// The amount of each order
const DEFAULT_ORDER_AMOUNT: u64 = 100;

// -----------
// | Helpers |
// -----------

/// Get the order side of the party
fn get_order_side(party_id: u64) -> OrderSide {
    match party_id {
        0 => OrderSide::Sell,
        1 => OrderSide::Buy,
        _ => unreachable!(),
    }
}

/// Get the ID to assign to the order
fn get_order_id(party_id: u64) -> Uuid {
    let oid = match party_id {
        0 => ORDER_ID1.to_string(),
        1 => ORDER_ID2.to_string(),
        _ => unreachable!(),
    };

    Uuid::parse_str(&oid).unwrap()
}

/// Create a dummy order for the match
fn get_order(side: OrderSide) -> Order {
    let quote_mint = biguint_from_hex_string(QUOTE_MINT_ADDR).unwrap();
    let base_mint = biguint_from_hex_string(BASE_MINT_ADDR).unwrap();

    let worst_case_price = match side {
        OrderSide::Buy => MOCK_EXECUTION_PRICE + 1.,
        OrderSide::Sell => MOCK_EXECUTION_PRICE - 1.,
    };

    Order {
        quote_mint,
        base_mint,
        side,
        amount: DEFAULT_ORDER_AMOUNT,
        worst_case_price: FixedPoint::from_f64_round_down(worst_case_price),
        timestamp: 10,
    }
}

/// Get the balance to insert into the wallet to cover the order
fn get_balance(order: &Order) -> Balance {
    let mint = order.send_mint().clone();
    let amount = match order.side {
        OrderSide::Buy => (order.amount as f64 * MOCK_EXECUTION_PRICE).ceil() as u64,
        OrderSide::Sell => order.amount,
    };

    Balance::new_from_mint_and_amount(mint, amount)
}

/// Get the fee for a wallet
///
/// TODO: Update when fees are implemented
fn get_fee(balance: &Balance) -> Fee {
    Fee {
        settle_key: BigUint::from(0u64),
        percentage_fee: FixedPoint::from_f64_round_down(0.01),
        gas_token_amount: 0,
        gas_addr: balance.mint.clone(),
    }
}

/// Create a wallet for the given party
fn create_wallet_for_party(party_id: u64) -> Wallet {
    let mut wallet = mock_empty_wallet();

    let side = get_order_side(party_id);
    let id = get_order_id(party_id);
    let order = get_order(side);
    let balance = get_balance(&order);
    let fee = get_fee(&balance);

    wallet.add_order(id, order.clone()).unwrap();
    wallet.add_balance(balance).unwrap();
    wallet.fees.push(fee);
    wallet
}

// ---------
// | Tests |
// ---------

/// Test that we can match orders via an MPC
async fn test_mpc_match(args: IntegrationTestArgs) -> Result<()> {
    let node = &args.mock_node;

    // Allocate a wallet for each party
    let mut wallet = create_wallet_for_party(args.party_id);
    allocate_wallet(&mut wallet, &args).await?;

    // Peer 1 starts a handshake for peer 2's order
    let order = get_order_id(PARTY1);
    if args.party_id == PARTY0 {
        let job = HandshakeExecutionJob::PerformHandshake { order };
        node.send_handshake_job(job).unwrap();
    }

    let mut reader = node.bus().subscribe("test".to_string());
    let _msg = reader.next_message().await;

    Ok(())
}

integration_test_async!(test_mpc_match);
