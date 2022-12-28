#![allow(clippy::empty_loop)]
mod errors;
mod exchanges;
mod reporter;
mod tokens;

use dotenv::from_filename;
use std::{thread, time};

use crate::{errors::ReporterError, exchanges::Exchange, reporter::PriceReporter, tokens::Token};

#[macro_use]
extern crate lazy_static;

#[tokio::main]
async fn main() -> Result<(), ReporterError> {
    from_filename("api_keys.env").ok();

    // Create a PriceReporter and copy a median receiver instance.
    let price_reporter =
        PriceReporter::new(Token::from_ticker("STG"), Token::from_ticker("USDC")).unwrap();
    let mut median_receiver = price_reporter.create_new_receiver(Exchange::Median);

    // Poll prices.
    thread::spawn(move || loop {
        thread::sleep(time::Duration::from_millis(100));
        let price_reports = price_reporter.peek_all().unwrap();
        println!(
            "Polled Median: {:.3} (B{:.3} C{:.3} K{:.3} O{:.3} U{:.3})",
            price_reports.get(&Exchange::Median).unwrap().midpoint_price,
            price_reports
                .get(&Exchange::Binance)
                .unwrap()
                .midpoint_price,
            price_reports
                .get(&Exchange::Coinbase)
                .unwrap()
                .midpoint_price,
            price_reports.get(&Exchange::Kraken).unwrap().midpoint_price,
            price_reports.get(&Exchange::Okx).unwrap().midpoint_price,
            price_reports
                .get(&Exchange::UniswapV3)
                .unwrap()
                .midpoint_price,
        );
    });

    // Stream prices.
    thread::spawn(move || loop {
        let _median_report = median_receiver.recv().unwrap();
        // println!(
        //     "Stream Median: {:.4} {}",
        //     median_report.midpoint_price, median_report.local_timestamp
        // );
    });

    loop {}
}
