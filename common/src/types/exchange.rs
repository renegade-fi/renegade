//! Defines exchanges used for price information

use std::{
    fmt::{self, Display},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use super::token::Token;
use crate::types::price::{Price, TimestampedPrice};

/// The identifier of an exchange
#[allow(clippy::missing_docs_in_private_items, missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Exchange {
    Binance,
    Coinbase,
    Kraken,
    Okx,
    UniswapV3,
    Renegade,
}

impl Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_str = match self {
            Exchange::Binance => String::from("binance"),
            Exchange::Coinbase => String::from("coinbase"),
            Exchange::Kraken => String::from("kraken"),
            Exchange::Okx => String::from("okx"),
            Exchange::UniswapV3 => String::from("uniswapv3"),
            Exchange::Renegade => String::from("renegade"),
        };
        write!(f, "{}", fmt_str)
    }
}

impl FromStr for Exchange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "binance" => Ok(Exchange::Binance),
            "coinbase" => Ok(Exchange::Coinbase),
            "kraken" => Ok(Exchange::Kraken),
            "okx" => Ok(Exchange::Okx),
            "uniswapv3" | "uniswap" => Ok(Exchange::UniswapV3),
            "renegade" => Ok(Exchange::Renegade),
            _ => Err(format!("Unknown exchange: {s}")),
        }
    }
}

/// The PriceReport is the universal format for price feeds from all external
/// exchanges.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PriceReport {
    /// The base Token
    pub base_token: Token,
    /// The quote Token
    pub quote_token: Token,
    /// The reported price
    pub price: Price,
    /// The time that this update was received by the relayer node,
    /// expected to be in milliseconds since the UNIX epoch
    pub local_timestamp: u64,
}

/// The state of the PriceReporter. The Nominal state means that enough
/// ExchangeConnections are reporting recent prices, so it is OK to proceed with
/// MPCs at the given price.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PriceReporterState {
    /// Enough reporters are correctly reporting to construct a price.
    Nominal(PriceReport),
    /// Not enough data has yet to be reported from the ExchangeConnections.
    /// Includes the number of ExchangeConnection reporters.
    NotEnoughDataReported(usize),
    /// At least one of the ExchangeConnection has not reported a recent enough
    /// report. Includes the current time_diff in milliseconds.
    DataTooStale(PriceReport, u64),
    /// There has been too much deviation in the prices between the exchanges;
    /// holding off until prices stabilize. Includes the current deviation
    /// as a fraction.
    TooMuchDeviation(PriceReport, f64),
    /// No reporter state, price pair is unsupported
    UnsupportedPair(Token, Token),
}

impl PriceReporterState {
    /// Get the price for a given reporter state, converting non-nominal states
    /// to error
    pub fn price(&self) -> Result<TimestampedPrice, String> {
        match self {
            PriceReporterState::Nominal(report) => Ok(TimestampedPrice::new(report.price)),
            _ => Err(format!("{self:?}")),
        }
    }
}

/// The state of an ExchangeConnection
///
/// The ExchangeConnection itself simply streams news PriceReports, and the
/// task of determining if the PriceReports have yet to arrive is the job of
/// the PriceReporter
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExchangeConnectionState {
    /// The ExchangeConnection is reporting as normal.
    Nominal(PriceReport),
    /// No data has yet to be reported from the ExchangeConnection.
    NoDataReported,
    /// This Exchange is unsupported for the given Token pair
    Unsupported,
}

impl Display for ExchangeConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_str = match self {
            ExchangeConnectionState::Nominal(price_report) => {
                format!("{:.4}", price_report.price)
            },
            ExchangeConnectionState::NoDataReported => String::from("NoDataReported"),
            ExchangeConnectionState::Unsupported => String::from("Unsupported"),
        };
        write!(f, "{}", fmt_str)
    }
}
