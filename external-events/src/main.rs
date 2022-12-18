//! This crate manages all external event reporting, including 1) price feeds from centralized
//! exchanges, 2) StarkWare events, including nullifier reveals in order to hang up MPCs, and 3)
//! Ethereum events, like sequencer rotation or L1 deposits.

mod errors;
mod exchanges;
mod reporters;
mod tokens;

use dotenv::from_filename;
use std::{thread, time};

use crate::{exchanges::Exchange, reporters::PriceReporter, tokens::Token};

fn main() {
    from_filename("api_keys.env").ok();

    // Create a few different reporters and receivers.
    let median_reporter = PriceReporter::new(Token::ETH, Token::USDC, None).unwrap();
    let binance_reporter =
        PriceReporter::new(Token::ETH, Token::USDC, Some(vec![Exchange::Binance])).unwrap();
    let coinbase_reporter =
        PriceReporter::new(Token::ETH, Token::USDC, Some(vec![Exchange::Coinbase])).unwrap();
    let kraken_reporter =
        PriceReporter::new(Token::ETH, Token::USDC, Some(vec![Exchange::Kraken])).unwrap();
    let okx_reporter =
        PriceReporter::new(Token::ETH, Token::USDC, Some(vec![Exchange::Okx])).unwrap();

    let mut median_receiver = median_reporter.create_new_receiver();
    // let mut binance_receiver = binance_reporter.create_new_receiver();
    // let mut coinbase_receiver = coinbase_reporter.create_new_receiver();
    // let mut kraken_receiver = kraken_reporter.create_new_receiver();
    // let mut okx_receiver = okx_reporter.create_new_receiver();

    // Poll prices.
    thread::spawn(move || loop {
        thread::sleep(time::Duration::from_millis(100));
        let median_report = median_reporter.peek().unwrap();
        let binance_report = binance_reporter.peek().unwrap();
        let coinbase_report = coinbase_reporter.peek().unwrap();
        let kraken_report = kraken_reporter.peek().unwrap();
        let okx_report = okx_reporter.peek().unwrap();
        println!(
            "Polled Median: {:.3}  ( B {:.3} C {:.3} K {:.3} O {:.3} )",
            median_report.midpoint_price,
            binance_report.midpoint_price,
            coinbase_report.midpoint_price,
            kraken_report.midpoint_price,
            okx_report.midpoint_price,
        );
    });

    // Stream prices.
    // thread::spawn(move || loop {
    //     let median_report = median_receiver.recv().unwrap();
    //     println!(
    //         "Stream Median: {:.4} {}",
    //         median_report.midpoint_price, median_report.local_timestamp
    //     );
    // });

    loop {}
}
