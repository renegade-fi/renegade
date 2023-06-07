//! The exchanges module defines individual ExchangeConnection logic, including all parsing logic
//! for price messages from both centralized and decentralized exchanges.
mod binance;
mod coinbase;
mod connection;
mod handlers_centralized;
mod handlers_decentralized;
mod kraken;
mod okx;

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

use super::reporter::Price;

/// List of all supported exchanges
pub static ALL_EXCHANGES: &[Exchange] = &[
    Exchange::Binance,
    Exchange::Coinbase,
    Exchange::Kraken,
    Exchange::Okx,
    Exchange::UniswapV3,
];

/// The identifier of an exchange
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum Exchange {
    /// Binance.
    Binance,
    /// Coinbase.
    Coinbase,
    /// Kraken.
    Kraken,
    /// Okx.
    Okx,
    /// UniswapV3.
    UniswapV3,
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

/// A helper struct that represents a stream of midpoint prices that may
/// be initialized at construction
#[derive(Debug)]
struct InitializablePriceStream<T: Stream<Item = Price> + Unpin> {
    /// The underlying stream
    stream: T,
    /// A buffered stream value, possibly used for initialization
    buffered_value: AtomicF64,
    /// Whether the buffered value has been consumed
    buffered_value_consumed: AtomicBool,
}

impl<T: Stream<Item = Price> + Unpin> Stream for InitializablePriceStream<T> {
    type Item = Price;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // Attempt to consume the buffered value
        if let Ok(_old_val) = this.buffered_value_consumed.compare_exchange(
            false, /* current */
            true,  /* new */
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            return Poll::Ready(Some(this.buffered_value.load(Ordering::Relaxed)));
        }

        T::poll_next(Pin::new(&mut this.stream), cx)
    }
}

impl<T: Stream<Item = Price> + Unpin> InitializablePriceStream<T> {
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
