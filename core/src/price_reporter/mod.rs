//! The price reporter module manages all external price feeds, including PriceReporter spin-up and
//! tear-down, websocket connections to all exchanges (both centralized and decentralized), and
//! aggregation of individual PriceReports into medians.

use self::tokens::Token;
pub mod errors;
pub mod exchanges;
pub mod jobs;
pub mod manager;
pub mod reporter;
pub mod tokens;
pub mod worker;

/// Get the topic name for a price report
pub fn price_report_topic_name(source: &str, base: Token, quote: Token) -> String {
    format!(
        "{}-price-report-{}-{}",
        source,
        base.get_addr(),
        quote.get_addr()
    )
}
