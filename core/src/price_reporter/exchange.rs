//! The exchanges module defines individual ExchangeConnection logic, including all parsing logic
//! for price messages from both centralized and decentralized exchanges.
mod binance;
mod coinbase;
mod connection;
mod kraken;
mod okx;
mod uni_v3;

use std::{
    fmt::{self, Display},
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use atomic_float::AtomicF64;
pub use connection::{get_current_time, ExchangeConnection, ExchangeConnectionState};

use futures_util::Stream;
use serde::{Deserialize, Serialize};

use self::{
    binance::BinanceConnection, coinbase::CoinbaseConnection, kraken::KrakenConnection,
    okx::OkxConnection, uni_v3::UniswapV3Connection,
};

use super::{
    errors::ExchangeConnectionError, reporter::Price, tokens::Token,
    worker::PriceReporterManagerConfig,
};

/// List of all supported exchanges
pub static ALL_EXCHANGES: &[Exchange] = &[
    Exchange::Binance,
    Exchange::Coinbase,
    Exchange::Kraken,
    Exchange::Okx,
    Exchange::UniswapV3,
];

/// The identifier of an exchange
#[allow(clippy::missing_docs_in_private_items, missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Exchange {
    Binance,
    Coinbase,
    Kraken,
    Okx,
    UniswapV3,
}

impl Exchange {
    /// Construct a new websocket connection for the given exchange
    pub async fn connect(
        &self,
        base_token: &Token,
        quote_token: &Token,
        config: &PriceReporterManagerConfig,
    ) -> Result<Box<dyn ExchangeConnection>, ExchangeConnectionError> {
        let base_token = base_token.clone();
        let quote_token = quote_token.clone();

        Ok(match self {
            Exchange::Binance => {
                Box::new(BinanceConnection::connect(base_token, quote_token, config).await?)
            }
            Exchange::Coinbase => {
                Box::new(CoinbaseConnection::connect(base_token, quote_token, config).await?)
            }
            Exchange::Kraken => {
                Box::new(KrakenConnection::connect(base_token, quote_token, config).await?)
            }
            Exchange::Okx => {
                Box::new(OkxConnection::connect(base_token, quote_token, config).await?)
            }
            Exchange::UniswapV3 => {
                Box::new(UniswapV3Connection::connect(base_token, quote_token, config).await?)
            }
        })
    }
}

impl Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_str = match self {
            Exchange::Binance => String::from("binance"),
            Exchange::Coinbase => String::from("coinbase"),
            Exchange::Kraken => String::from("kraken"),
            Exchange::Okx => String::from("okx"),
            Exchange::UniswapV3 => String::from("uniswapv3"),
        };
        write!(f, "{}", fmt_str)
    }
}

/// The type that a price stream should return
type PriceStreamType = Result<Price, ExchangeConnectionError>;

/// A helper struct that represents a stream of midpoint prices that may
/// be initialized at construction
#[derive(Debug)]
struct InitializablePriceStream<T: Stream<Item = PriceStreamType> + Unpin> {
    /// The underlying stream
    stream: T,
    /// A buffered stream value, possibly used for initialization
    buffered_value: AtomicF64,
    /// Whether the buffered value has been consumed
    buffered_value_consumed: AtomicBool,
}

impl<T: Stream<Item = PriceStreamType> + Unpin> Stream for InitializablePriceStream<T> {
    type Item = PriceStreamType;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Attempt to consume the buffered value
        if this
            .buffered_value_consumed
            .compare_exchange(
                false, /* current */
                true,  /* new */
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return Poll::Ready(Some(Ok(this.buffered_value.load(Ordering::Relaxed))));
        }

        T::poll_next(Pin::new(&mut this.stream), cx)
    }
}

impl<T: Stream<Item = PriceStreamType> + Unpin> InitializablePriceStream<T> {
    /// Construct a new stream without an initial value
    pub fn new(stream: T) -> Self {
        Self {
            stream,
            buffered_value: AtomicF64::new(0.0),
            buffered_value_consumed: AtomicBool::new(true),
        }
    }

    /// Construct a new stream with an initial value
    pub fn new_with_initial(stream: T, initial_value: Price) -> Self {
        Self {
            stream,
            buffered_value: AtomicF64::new(initial_value),
            buffered_value_consumed: AtomicBool::new(false),
        }
    }
}
