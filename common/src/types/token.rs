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
    sync::{LazyLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
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
pub type ExchangeSupport = HashMap<Exchange, String>;

/// A type alias representing an `RwLock` wrapped in a `LazyLock`,
/// allowing for it to be used as a primitive for mutable static variables
type RwStatic<T> = LazyLock<RwLock<T>>;

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
pub static TOKEN_REMAPS: RwStatic<BiMap<String, String>> =
    RwStatic::new(|| RwLock::new(BiMap::new()));

/// The decimal mapping for the given environment, maps from the token address
/// to the number of decimals the token uses (fixed-point offset)
pub static ADDR_DECIMALS_MAP: RwStatic<HashMap<String, u8>> =
    RwStatic::new(|| RwLock::new(HashMap::new()));

/// The mapping from ERC-20 ticker to the set of exchanges that list the token,
/// along with the the ticker used to fetch the token's price from the exchange
pub static EXCHANGE_SUPPORT_MAP: RwStatic<HashMap<String, ExchangeSupport>> =
    RwStatic::new(|| RwLock::new(HashMap::new()));

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
        let token_remap = read_token_remap();
        let addr = token_remap
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
    pub fn get_ticker(&self) -> Option<String> {
        let token_remap = read_token_remap();
        token_remap.get_by_left(&self.get_addr()).cloned()
    }

    /// Returns the ERC-20 `decimals` field, if available.
    pub fn get_decimals(&self) -> Option<u8> {
        let addr_decimals_map = read_token_decimals_map();
        addr_decimals_map.get(&self.get_addr()).copied()
    }

    /// Returns true if the Token has a Renegade-native ticker.
    pub fn is_named(&self) -> bool {
        self.get_ticker().is_some()
    }

    /// Returns true if the Token is a stablecoin.
    pub fn is_stablecoin(&self) -> bool {
        self.get_ticker().map_or(false, |ticker| STABLECOIN_TICKERS.contains(&ticker.as_str()))
    }

    /// Returns the set of Exchanges that support this token.
    pub fn supported_exchanges(&self) -> HashSet<Exchange> {
        if !self.is_named() {
            // Uniswap is always supported
            return HashSet::from([Exchange::UniswapV3]);
        }

        let ticker = self.get_ticker().unwrap();
        let mut supported_exchanges: HashSet<Exchange> = read_exchange_support()
            .get(&ticker)
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
        read_exchange_support()
            .get(&ticker)
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

/// Returns a read lock quard to the token remap
pub fn read_token_remap<'a>() -> RwLockReadGuard<'a, BiMap<String, String>> {
    TOKEN_REMAPS.read().expect("Token remap lock poisoned")
}

/// Returns a read lock quard to the decimal map
pub fn read_token_decimals_map<'a>() -> RwLockReadGuard<'a, HashMap<String, u8>> {
    ADDR_DECIMALS_MAP.read().expect("Decimal map lock poisoned")
}

/// Returns a read lock quard to the exchange support map
pub fn read_exchange_support<'a>() -> RwLockReadGuard<'a, HashMap<String, ExchangeSupport>> {
    EXCHANGE_SUPPORT_MAP.read().expect("Exchange support map lock poisoned")
}

/// Returns a write lock quard to the token remap
pub fn write_token_remap<'a>() -> RwLockWriteGuard<'a, BiMap<String, String>> {
    TOKEN_REMAPS.write().expect("Token remap lock poisoned")
}

/// Returns a write lock quard to the decimal map
pub fn write_token_decimals_map<'a>() -> RwLockWriteGuard<'a, HashMap<String, u8>> {
    ADDR_DECIMALS_MAP.write().expect("Decimal map lock poisoned")
}

/// Returns a write lock quard to the exchange support map
pub fn write_exchange_support<'a>() -> RwLockWriteGuard<'a, HashMap<String, ExchangeSupport>> {
    EXCHANGE_SUPPORT_MAP.write().expect("Exchange support map lock poisoned")
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
