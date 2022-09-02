use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use circuits::{
    types::{Balance, Order, OrderSide, SingleMatchResult, Match},
    circuits::valid_match_small::SmallValidMatchCircuit
};

#[allow(dead_code)]
fn valid_match_small_proving_time(c: &mut Criterion) {
    // Create mock data to prove against
    let QUOTE_MINT = 1;
    let BASE_MINT = 2;

    let order1 = Order { quote_mint: QUOTE_MINT, base_mint: BASE_MINT, side: OrderSide::Buy, amount: 5, price: 11 };
    let order2 = Order { quote_mint: QUOTE_MINT, base_mint: BASE_MINT, side: OrderSide::Sell, amount: 3, price: 9 };

    let balance1 = Balance { mint: QUOTE_MINT, amount: 50 };
    let balance2 = Balance { mint: BASE_MINT, amount: 3 };

    let match_result = SingleMatchResult {
        buy_side1: Match { mint: BASE_MINT, amount: 3, side: OrderSide::Buy },
        sell_side1: Match { mint: QUOTE_MINT, amount: 30, side: OrderSide::Sell },
        buy_side2: Match { mint: QUOTE_MINT, amount: 30, side: OrderSide::Buy },
        sell_side2: Match { mint: BASE_MINT, amount: 3, side: OrderSide::Sell },
    };

    // Build the proving key
    println!("Building circuit and proving key...");
    let proving_key = SmallValidMatchCircuit::create_proving_key().unwrap();

    println!("Starting benchmark...");
    c.bench_function("VALID_MATCH single order", |b| b.iter(
        || {
            let mut match_circuit = SmallValidMatchCircuit::new(
                match_result.clone(), balance1.clone(), balance2.clone(), order1.clone(), order2.clone()
            );
            match_circuit.create_proof(black_box(&proving_key)).unwrap();
        })
    );
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::new(300 /* secs */, 0 /* nanos */));
    targets = valid_match_small_proving_time
);
criterion_main!(benches);