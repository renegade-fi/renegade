//! The Token is the cross-exchange abstraction of a fungible token. Since many
//! different exchanges define different standards for token names, tickers,
//! etc., we use the Ethereum mainnet ERC-20 address as the authoritative
//! identifier for each token. We map each of these contract addresses
//! into ticker names for consumption by each centralized exchange, as
//! appropriate.
//!
//! Tokens fall under two different categories: "Named Tokens" that have
//! centralized and decentralized exchange price feed support, and "Unnamed
//! Tokens" that only have decentralized exchange price feed support. We
//! explicitly name all Named Tokens below, as the relayer need to manually map
//! these ERC-20 addresses into websocket subscription requests.
//!
//! In general, Named Tokens use all exchanges where they are listed, whereas
//! Unnamed Tokens only use Uniswap V3 for the price feed.
use bimap::BiMap;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    iter,
    sync::OnceLock,
};

use crate::biguint_to_str_addr;

use super::exchange::{Exchange, ALL_EXCHANGES};

/// A helper enum to describe the state of each ticker on each Exchange. Same
/// means that the ERC-20 and Exchange tickers are the same, Renamed means that
/// the Exchange ticker is different from the underlying ERC-20, and Unsupported
/// means that the asset is not supported on the Exchange.
#[derive(Clone, Copy, Debug)]
pub enum ExchangeTicker {
    /// The Exchange-native ticker is the same as the ERC-20 ticker.
    Same,
    /// The Exchange-native ticker is different from the ERC-20 ticker.
    Renamed(&'static str),
    /// The Exchange does not support this Token.
    Unsupported,
}

// We populate three global heap-allocated structs for convenience and metadata
// lookup. The first is a bidirectional map between the ERC-20 contract address
// and the ERC-20 ticker. The second is a HashMap between the ERC-20 contract
// address and the number of decimals (fixed-point offset). The third is a
// HashMap between the ERC-20 ticker and each Exchange's expected name for each
// ticker.

/// The remapping of tickers between exchanges. The layout of `TICKER_NAMES` is
/// (Renegade Ticker, Binance Ticker, Coinbase Ticker, Kraken Ticker, Okx
/// Ticker), where "Renegade Ticker" denotes the ticker expected in the Renegade
/// token remapping used.
pub static TICKER_NAMES: &[(
    &str,
    ExchangeTicker,
    ExchangeTicker,
    ExchangeTicker,
    ExchangeTicker,
)] = &[
    // L1
    (
        "WBTC",
        ExchangeTicker::Renamed("BTC"),
        ExchangeTicker::Renamed("BTC"),
        ExchangeTicker::Renamed("BTC"),
        ExchangeTicker::Renamed("BTC"),
    ),
    (
        "WETH",
        ExchangeTicker::Renamed("ETH"),
        ExchangeTicker::Renamed("ETH"),
        ExchangeTicker::Renamed("ETH"),
        ExchangeTicker::Renamed("ETH"),
    ),
    (
        "BNB",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
    ),
    (
        "MATIC",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    // LSDs
    ("LDO", ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same),
    // Stables
    (
        "USDC",
        ExchangeTicker::Same,
        ExchangeTicker::Renamed("USD"), // USDC has 1:1 peg with USD on Coinbase
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "USDT",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "USD",
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    // Oracles
    (
        "LINK",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    // DeFi Trading
    ("UNI", ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same),
    ("CRV", ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same),
    (
        "DYDX",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "SUSHI",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "1INCH",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    // DeFi Lending
    (
        "AAVE",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "COMP",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    ("MKR", ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same),
    // DeFi Other
    (
        "TORN",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
    ),
    // Bridges
    ("REN", ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same),
    // Misc
    (
        "SHIB",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    ("ENS", ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same, ExchangeTicker::Same),
    (
        "MANA",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
];

/// The token remapping for the given environment, maps from the token address
/// to the ticker of the token
pub static TOKEN_REMAPS: OnceLock<BiMap<String, String>> = OnceLock::new();

/// The decimal mapping for the given environment, maps from the token address
/// to the number of decimals the token uses
pub static ADDR_DECIMALS_MAP: OnceLock<HashMap<String, u8>> = OnceLock::new();

lazy_static! {
    static ref EXCHANGE_TICKERS: HashMap<Exchange, HashMap<String, String>> = {
        let mut exchange_tickers = HashMap::<Exchange, HashMap<String, String>>::new();
        for exchange in [Exchange::Binance, Exchange::Coinbase, Exchange::Kraken, Exchange::Okx] {
            exchange_tickers.insert(exchange, HashMap::<String, String>::new());
        }
        for (erc20_ticker, binance_ticker, coinbase_ticker, kraken_ticker, okx_ticker) in
            TICKER_NAMES.iter()
        {
            let process_ticker = move |ticker: ExchangeTicker| -> Option<&'static str> {
                match ticker {
                    ExchangeTicker::Same => Some(erc20_ticker),
                    ExchangeTicker::Renamed(ticker) => Some(ticker),
                    ExchangeTicker::Unsupported => None,
                }
            };
            if let Some(binance_ticker) = process_ticker(*binance_ticker) {
                exchange_tickers
                    .get_mut(&Exchange::Binance)
                    .unwrap()
                    .insert(String::from(*erc20_ticker), String::from(binance_ticker));
            }
            if let Some(coinbase_ticker) = process_ticker(*coinbase_ticker) {
                exchange_tickers
                    .get_mut(&Exchange::Coinbase)
                    .unwrap()
                    .insert(String::from(*erc20_ticker), String::from(coinbase_ticker));
            }
            if let Some(kraken_ticker) = process_ticker(*kraken_ticker) {
                exchange_tickers
                    .get_mut(&Exchange::Kraken)
                    .unwrap()
                    .insert(String::from(*erc20_ticker), String::from(kraken_ticker));
            }
            if let Some(okx_ticker) = process_ticker(*okx_ticker) {
                exchange_tickers
                    .get_mut(&Exchange::Okx)
                    .unwrap()
                    .insert(String::from(*erc20_ticker), String::from(okx_ticker));
            }
        }
        exchange_tickers
    };
}

/// The core Token abstraction, used for unambiguous definition of an ERC-20
/// asset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    /// The ERC-20 address of the Token.
    pub addr: String,
}

impl Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl Token {
    /// Given an ERC-20 contract address, returns a new Token
    pub fn from_addr(addr: &str) -> Self {
        Self { addr: String::from(addr).to_lowercase() }
    }

    /// Given an ERC-20 contract address represented as a `BigUint`, returns a
    /// Token
    pub fn from_addr_biguint(addr: &BigUint) -> Self {
        Self { addr: biguint_to_str_addr(addr) }
    }

    /// Given an ERC-20 ticker, returns a new Token.
    pub fn from_ticker(ticker: &str) -> Self {
        let addr = TOKEN_REMAPS
            .get()
            .unwrap()
            .get_by_right(ticker)
            .expect("Ticker is not supported; specify unnamed token by ERC-20 address using from_addr instead.");

        Self { addr: addr.to_string() }
    }

    /// Returns the ERC-20 address.
    pub fn get_addr(&self) -> &str {
        &self.addr
    }

    /// Returns the ERC-20 ticker, if available. Note that it is OK if certain
    /// Tickers do not have any ERC-20 ticker, as we support long-tail
    /// assets.
    pub fn get_ticker(&self) -> Option<&str> {
        TOKEN_REMAPS.get().unwrap().get_by_left(&self.addr).map(|x| x.as_str())
    }

    /// Returns the ERC-20 `decimals` field, if available.
    pub fn get_decimals(&self) -> Option<u8> {
        ADDR_DECIMALS_MAP.get().unwrap().get(self.get_addr()).copied()
    }

    /// Returns true if the Token has a Renegade-native ticker.
    pub fn is_named(&self) -> bool {
        self.get_ticker().is_some()
    }

    /// Returns the set of Exchanges that support this token.
    pub fn supported_exchanges(&self) -> HashSet<Exchange> {
        // Uniswap is always supported
        let mut exchanges: HashSet<Exchange> = iter::once(Exchange::UniswapV3).collect();
        if !self.is_named() {
            return exchanges;
        }

        let ticker = self.get_ticker().unwrap();
        ALL_EXCHANGES
            .iter()
            .filter(|&&exchange| exchange != Exchange::UniswapV3)
            .filter(|&exchange| EXCHANGE_TICKERS.get(exchange).unwrap().contains_key(ticker))
            .for_each(|&exchange| {
                exchanges.insert(exchange);
            });

        exchanges
    }

    /// Returns the ticker, in accordance with what each Exchange expects. This
    /// requires hard-coding and manual lookup, since CEXes typically do not
    /// support indexing by ERC-20 address. If the ticker is not supported
    /// by the Exchange, returns None.
    pub fn get_exchange_ticker(&self, exchange: Exchange) -> String {
        // If there is not a Renegade-native ticker, then the token must be Unnamed.
        if !self.is_named() {
            panic!("Tried to get_exchange_ticker({}) for an unnamed Token.", exchange);
        }

        EXCHANGE_TICKERS
            .get(&exchange)
            .unwrap()
            .get(self.get_ticker().unwrap())
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "Tried to get_exchange_ticker({}) for a named token, \
                    but the token is not supported by the Exchange.",
                    exchange
                )
            })
    }

    /// Converts the amount of the token as an f64, accounting for the
    /// associated number of decimals.
    ///
    /// Note that due to conversion to f64, the result may lose precision.
    pub fn convert_to_decimal(&self, amount: u128) -> f64 {
        let decimals = self.get_decimals().unwrap_or_default();
        let decimal_adjustment = 10u128.pow(decimals as u32);
        amount as f64 / decimal_adjustment as f64
    }
}

// -----------
// | HELPERS |
// -----------

/// Returns true if the given pair of Tokens is named, indicating that
/// the pair should be supported on centralized exchanges.
pub fn is_pair_named(base: &Token, quote: &Token) -> bool {
    base.is_named() && quote.is_named()
}
