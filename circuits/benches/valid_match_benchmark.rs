use std::time::Duration;

use ark_groth16::{prepare_verifying_key, verify_proof};
use ark_r1cs_std::fields::fp::FpVar;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use circuits::{
    types::{Wallet, Balance, Order, OrderSide, SystemField},
    circuits::valid_match::ValidMatchCircuit
};

fn valid_match_proving_time(c: &mut Criterion) {
    // Create two wallets to benchmark against
    let max_balances = 20;
    let max_orders = 20;

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

    let wallet1_hash_var = SystemField::from(wallet1_hash.clone());
    let wallet2_hash_var = SystemField::from(wallet2_hash.clone());

    // Build the proving key
    println!("Building circuit and proving key...");
    let proving_key = ValidMatchCircuit::create_proving_key(max_balances, max_orders).unwrap();

    let verifying_key = prepare_verifying_key(&proving_key.vk);

    println!("Starting benchmark...");
    c.bench_function("VALID_MATCH proof generation n_balances = 20, n_orders = 20", |b| b.iter(
        || {
            let match_circuit = ValidMatchCircuit::new(wallet1.clone(), wallet2.clone(), wallet1_hash.clone(), wallet2_hash.clone());
            let proof = match_circuit.create_proof(black_box(&proving_key)).unwrap();
            assert!(
                verify_proof(&verifying_key, &proof, &vec![wallet1_hash_var, wallet2_hash_var])
                    .unwrap()
            );
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