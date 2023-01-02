#![allow(clippy::empty_loop)]
mod errors;
mod exchanges;
mod reporter;
mod tokens;

use std::{thread, time};

use crate::{
    exchanges::{Exchange, ALL_EXCHANGES},
    reporter::PriceReporter,
    tokens::Token,
};

#[macro_use]
extern crate lazy_static;

async fn poll_or_stream_prices(should_poll: bool) {
    let price_reporter = PriceReporter::new(Token::from_ticker("WETH"), Token::from_ticker("USDC"));
    println!(
        "Supported exchanges: {:?}",
        price_reporter.get_supported_exchanges()
    );
    println!(
        "Healthy exchanges: {:?}",
        price_reporter.get_healthy_exchanges()
    );

    if should_poll {
        thread::spawn(move || loop {
            let exchange_states = price_reporter.peek_all_exchanges();
            let median_price_report = price_reporter.peek_median();
            println!("{}", "=".repeat(80));
            println!("Median: {}", median_price_report);
            println!("{}", "-".repeat(80));
            println!(
                "{:<14} | {:<14} | {:<14} | {:<14} | {:<14}",
                format!("{}", exchange_states.get(&Exchange::Binance).unwrap()),
                format!("{}", exchange_states.get(&Exchange::Coinbase).unwrap()),
                format!("{}", exchange_states.get(&Exchange::Kraken).unwrap()),
                format!("{}", exchange_states.get(&Exchange::Okx).unwrap()),
                format!("{}", exchange_states.get(&Exchange::UniswapV3).unwrap()),
            );
            thread::sleep(time::Duration::from_millis(100));
        });
    } else {
        let mut median_receiver = price_reporter.create_new_median_receiver();
        thread::spawn(move || loop {
            let median_report = median_receiver.recv().unwrap();
            println!(
                "{:<10} {:.4} {}",
                "Median:", median_report.midpoint_price, median_report.local_timestamp
            );
        });
        for exchange in ALL_EXCHANGES.iter() {
            let mut receiver = price_reporter.create_new_exchange_receiver(*exchange);
            thread::spawn(move || loop {
                let report = receiver.recv().unwrap();
                println!(
                    "{:<10} {:.4} {}",
                    format!("{}:", exchange),
                    report.midpoint_price,
                    report.local_timestamp
                );
            });
        }
    }

    loop {}
}

#[tokio::main]
async fn main() {
    dotenv::from_filename("secrets.env").expect("Cannot read secrets from secrets.env");
    poll_or_stream_prices(true).await;
}
