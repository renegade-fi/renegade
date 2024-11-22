//! Represents a token in the Renegade system
//!
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
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    sync::OnceLock,
};
use util::hex::biguint_to_hex_addr;

use super::exchange::Exchange;

// ---------
// | Types |
// ---------

/// A type alias representing the set of supported exchanges for a
/// given token.
/// The type is a mapping from exchanges to the ticker used to fetch the
/// token's price from that exchange
type ExchangeSupport = HashMap<Exchange, String>;

// ----------------
// | Quote Tokens |
// ----------------

/// USDC ticker
pub const USDC_TICKER: &str = "USDC";
/// USDT ticker
pub const USDT_TICKER: &str = "USDT";
/// USD ticker
///
/// We don't actually allow USD as a quote asset since it's not an ERC20,
/// but it is used as a quote in some exchanges, so we must be able to
/// stream prices for it.
pub const USD_TICKER: &str = "USD";

/// The set of tickers of stablecoins for which price conversion may
/// be invoked if they are the quote
pub const STABLECOIN_TICKERS: &[&str] = &[USDC_TICKER, USDT_TICKER];

/// The token remapping for the given environment, maps from the token address
/// to the ticker of the token
pub static TOKEN_REMAPS: OnceLock<BiMap<String, String>> = OnceLock::new();

/// The decimal mapping for the given environment, maps from the token address
/// to the number of decimals the token uses (fixed-point offset)
pub static ADDR_DECIMALS_MAP: OnceLock<HashMap<String, u8>> = OnceLock::new();

/// The mapping from ERC-20 ticker to the set of exchanges that list the token,
/// along with the the ticker used to fetch the token's price from the exchange
pub static EXCHANGE_SUPPORT_MAP: OnceLock<HashMap<String, ExchangeSupport>> = OnceLock::new();

/// The core Token abstraction, used for unambiguous definition of an ERC-20
/// asset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Token {
    /// The ERC-20 address of the Token.
    pub addr: String,
}

impl Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_addr())
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
        Self { addr: biguint_to_hex_addr(addr).to_lowercase() }
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
    pub fn get_addr(&self) -> String {
        self.addr.to_lowercase()
    }

    /// Returns the ERC-20 ticker, if available. Note that it is OK if certain
    /// Tickers do not have any ERC-20 ticker, as we support long-tail
    /// assets.
    pub fn get_ticker(&self) -> Option<&str> {
        TOKEN_REMAPS.get().unwrap().get_by_left(&self.get_addr()).map(|x| x.as_str())
    }

    /// Returns the ERC-20 `decimals` field, if available.
    pub fn get_decimals(&self) -> Option<u8> {
        ADDR_DECIMALS_MAP.get().unwrap().get(&self.get_addr()).copied()
    }

    /// Returns true if the Token has a Renegade-native ticker.
    pub fn is_named(&self) -> bool {
        self.get_ticker().is_some()
    }

    /// Returns true if the Token is a stablecoin.
    pub fn is_stablecoin(&self) -> bool {
        self.get_ticker().map_or(false, |ticker| STABLECOIN_TICKERS.contains(&ticker))
    }

    /// Returns the set of Exchanges that support this token.
    pub fn supported_exchanges(&self) -> HashSet<Exchange> {
        if !self.is_named() {
            // Uniswap is always supported
            return HashSet::from([Exchange::UniswapV3]);
        }

        let ticker = self.get_ticker().unwrap();
        let mut supported_exchanges: HashSet<Exchange> = get_exchange_support()
            .get(ticker)
            .map(|exchanges| exchanges.keys().copied().collect())
            .unwrap_or_default();
        supported_exchanges.insert(Exchange::UniswapV3);

        supported_exchanges
    }

    /// Returns the ticker, in accordance with what each Exchange expects. This
    /// requires manual lookup, since CEXes typically do not support indexing
    /// by ERC-20 address. If the ticker is not supported by the Exchange,
    /// returns None.
    pub fn get_exchange_ticker(&self, exchange: Exchange) -> Option<String> {
        // If there is not a Renegade-native ticker, then the token must be Unnamed.
        if !self.is_named() {
            panic!("Tried to get_exchange_ticker({}) for an unnamed Token.", exchange);
        }

        let ticker = self.get_ticker().unwrap();
        get_exchange_support()
            .get(ticker)
            .and_then(|supported_exchanges| supported_exchanges.get(&exchange).cloned())
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

/// Returns a reference to the exchange support map,
/// unwrapping the `OnceLock`.
pub fn get_exchange_support<'a>() -> &'a HashMap<String, ExchangeSupport> {
    EXCHANGE_SUPPORT_MAP.get().unwrap()
}

/// Returns true if the given pair of Tokens is named, indicating that
/// the pair should be supported on centralized exchanges.
pub fn is_pair_named(base: &Token, quote: &Token) -> bool {
    base.is_named() && quote.is_named()
}

/// Returns the default stable quote asset for the given exchange.
pub fn default_exchange_stable(exchange: &Exchange) -> Token {
    match exchange {
        Exchange::Binance => Token::from_ticker(USDT_TICKER),
        Exchange::Coinbase => Token::from_ticker(USD_TICKER),
        Exchange::Kraken => Token::from_ticker(USD_TICKER),
        Exchange::Okx => Token::from_ticker(USDT_TICKER),
        _ => panic!("No default stable quote asset for exchange: {:?}", exchange),
    }
}
