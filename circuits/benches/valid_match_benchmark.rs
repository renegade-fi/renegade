use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use circuits::{
    types::{Wallet, Balance, Order, OrderSide},
    circuits::valid_match::ValidMatchCircuit
};

#[allow(dead_code)]
fn valid_match_proving_time(c: &mut Criterion) {
    // Create two wallets to benchmark against
    let max_balances = 1;
    let max_orders = 1;

    let wallet1 = Wallet::new_with_bounds(
        vec![Balance { amount: 50, mint: 1 }],
        vec![Order { quote_mint: 1, base_mint: 2, amount: 5, price: 10, side: OrderSide::Buy }],
        max_balances,
        max_orders
    );

    let wallet2 = Wallet::new_with_bounds(
        vec![Balance { amount: 10, mint: 2 }], 
        vec![Order { quote_mint: 1, base_mint: 2, amount: 3, price: 5, side: OrderSide::Sell} ], 
        max_balances,
        max_orders
    );

    let wallet1_hash = wallet1.hash();
    let wallet2_hash = wallet2.hash();

    // Build the proving key
    println!("Building circuit and proving key...");
    let proving_key = ValidMatchCircuit::create_proving_key(max_balances, max_orders).unwrap();

    println!("Starting benchmark...");
    c.bench_function("VALID_MATCH proof generation n_balances = 1, n_orders = 1", |b| b.iter(
        || {
            let match_circuit = ValidMatchCircuit::new(wallet1.clone(), wallet2.clone(), wallet1_hash.clone(), wallet2_hash.clone());
            match_circuit.create_proof(black_box(&proving_key)).unwrap();
        })
    );
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::new(300 /* secs */, 0 /* nanos */));
    targets = valid_match_proving_time
);
criterion_main!(benches);