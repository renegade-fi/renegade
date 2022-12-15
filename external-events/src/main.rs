//! This crate manages all external event reporting, including 1) price feeds from exchanges like
//! Binance and Coinbase, 2) StarkWare events, including nullifier reveals in order to hang up
//! MPCs, and 3) Ethereum events, like sequencer rotation or L1 deposits.

mod errors;
mod exchanges;
mod reporters;
mod tokens;

use std::{thread, time};

use crate::{exchanges::Exchange, reporters::PriceReporter, tokens::Token};

fn main() {
    let mut binance_reporter =
        PriceReporter::new(Token::ETH, Token::USDC, Exchange::Binance).unwrap();
    loop {
        thread::sleep(time::Duration::from_millis(100));
        println!(
            "Midpoint: Binance = {:.4}",
            binance_reporter
                .get_current_report()
                .unwrap()
                .midpoint_price
        );
    }
}
