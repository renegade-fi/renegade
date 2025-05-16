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
use alloy::primitives::Address;
use bimap::BiMap;
use constants::NATIVE_ASSET_ADDRESS;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    hash::{Hash, Hasher},
    sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use util::{
    concurrency::RwStatic,
    hex::{biguint_from_hex_string, biguint_to_hex_addr},
    serde::{deserialize_str_lower, serialize_str_lower},
};

use super::chain::Chain;
use super::exchange::Exchange;

// ---------
// | Types |
// ---------

/// A type alias representing the set of supported exchanges for a
/// given token.
/// The type is a mapping from exchanges to the ticker used to fetch the
/// token's price from that exchange
pub type ExchangeSupport = HashMap<Exchange, String>;

/// A type alias representing the mapping from a chain to a mapping from the
/// token address to the ticker of the token
pub type TokenRemapsByChain = HashMap<Chain, BiMap<String, String>>;

/// A type alias representing the mapping from a chain to a mapping from the
/// token address to the number of decimals the token uses (fixed-point offset)
pub type TokenDecimalsByChain = HashMap<Chain, HashMap<String, u8>>;

/// A type alias representing the mapping from a token ticker to the set of
/// exchanges that list the token, along with the the ticker used to fetch the
/// token's price from the exchange
pub type ExchangeSupportMap = HashMap<String, ExchangeSupport>;

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

/// Maps a chain to a mapping from the token address to the ticker of the token
pub static TOKEN_REMAPS_BY_CHAIN: RwStatic<TokenRemapsByChain> =
    RwStatic::new(|| RwLock::new(HashMap::new()));

/// Maps a chain to a mapping from the token address to the number of decimals
/// the token uses (fixed-point offset)
pub static DECIMALS_BY_CHAIN: RwStatic<TokenDecimalsByChain> =
    RwStatic::new(|| RwLock::new(HashMap::new()));

/// The mapping from ERC-20 ticker to the set of exchanges that list the token,
/// along with the the ticker used to fetch the token's price from the exchange
pub static EXCHANGE_SUPPORT_MAP: RwStatic<ExchangeSupportMap> =
    RwStatic::new(|| RwLock::new(HashMap::new()));

/// Holds the "default" chain once it's been configured.
pub static DEFAULT_CHAIN: OnceLock<Chain> = OnceLock::new();

/// The core Token abstraction, used for unambiguous definition of an ERC-20
/// asset.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    /// The ERC-20 address of the Token.
    #[serde(deserialize_with = "deserialize_str_lower", serialize_with = "serialize_str_lower")]
    pub addr: String,
    /// The chain the token is on.
    #[serde(default = "default_chain")]
    pub chain: Chain,
}

impl Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_addr())
    }
}

impl Token {
    /// Create a new Token from an ERC-20 contract address
    pub fn new(addr: &str, chain: Chain) -> Self {
        Self { addr: String::from(addr).to_lowercase(), chain }
    }

    /// Get the USDC token
    pub fn usdc() -> Self {
        Self::from_ticker(USDC_TICKER)
    }

    /// Get the USDT token
    pub fn usdt() -> Self {
        Self::from_ticker(USDT_TICKER)
    }

    /// Return whether the token represents the native asset
    pub fn is_native_asset(&self) -> bool {
        self.addr.to_lowercase() == NATIVE_ASSET_ADDRESS.to_lowercase()
    }

    /// Given an ERC-20 contract address, returns a new Token
    pub fn from_addr(addr: &str) -> Self {
        Self::new(addr, default_chain())
    }

    /// Given an ERC-20 contract address, returns a new Token on a specific
    /// chain.
    pub fn from_addr_on_chain(addr: &str, chain: Chain) -> Self {
        Self::new(addr, chain)
    }

    /// Given an ERC-20 contract address represented as a `BigUint`, returns a
    /// Token
    pub fn from_addr_biguint(addr: &BigUint) -> Self {
        Self::new(&biguint_to_hex_addr(addr), default_chain())
    }

    /// Given an ERC-20 contract address represented as a `BigUint`, returns a
    /// Token
    pub fn from_addr_biguint_on_chain(addr: &BigUint, chain: Chain) -> Self {
        Self::new(&biguint_to_hex_addr(addr), chain)
    }

    /// Given an ERC-20 ticker, returns a new Token.
    pub fn from_ticker(ticker: &str) -> Self {
        let chain = default_chain();
        let remaps = read_token_remaps();
        let token_map = remaps.get(&chain).expect("Chain has not been setup");
        let addr = token_map
            .get_by_right(ticker)
            .expect("Ticker is not supported; specify unnamed token by ERC-20 address using from_addr instead.");

        Self::new(addr, chain)
    }

    /// Given an ERC-20 ticker, returns a new Token on a specific chain.
    pub fn from_ticker_on_chain(ticker: &str, chain: Chain) -> Self {
        let remaps = read_token_remaps();
        let token_map = remaps.get(&chain).expect("Chain has not been setup");
        let addr = token_map.get_by_right(ticker).expect("Ticker could not be found on chain");

        Self::new(addr, chain)
    }

    /// Returns the ERC-20 address.
    pub fn get_addr(&self) -> String {
        self.addr.to_lowercase()
    }

    /// Get a `BigUint` representation of the token address
    pub fn get_addr_biguint(&self) -> BigUint {
        biguint_from_hex_string(&self.get_addr()).expect("invalid token address in mapping")
    }

    /// Get the alloy compatible address
    pub fn get_alloy_address(&self) -> Address {
        self.addr.parse::<Address>().expect("invalid token address in mapping")
    }

    /// Returns the ERC-20 ticker, if available. Note that it is OK if certain
    /// Tickers do not have any ERC-20 ticker, as we support long-tail
    /// assets.
    pub fn get_ticker(&self) -> Option<String> {
        let remaps = read_token_remaps();
        remaps.get(&self.chain).and_then(|remap| remap.get_by_left(&self.get_addr()).cloned())
    }

    /// Returns the ERC-20 `decimals` field by scanning the default chain's
    /// decimals.
    pub fn get_decimals(&self) -> Option<u8> {
        let decimals_map = read_token_decimals_map();
        decimals_map.get(&self.chain).and_then(|map| map.get(&self.get_addr()).copied())
    }

    /// Returns the chain the token is on.
    pub fn get_chain(&self) -> Chain {
        self.chain
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

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.addr.to_lowercase() == other.addr.to_lowercase()
    }
}

impl Eq for Token {}

impl Hash for Token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.to_lowercase().hash(state);
    }
}

// -----------
// | HELPERS |
// -----------

/// Returns a read lock guard to the per-chain token remaps
pub fn read_token_remaps<'a>() -> RwLockReadGuard<'a, TokenRemapsByChain> {
    TOKEN_REMAPS_BY_CHAIN.read().expect("Token remaps lock poisoned")
}

/// Get all tokens in the remap
pub fn get_all_tokens() -> Vec<Token> {
    let remaps = read_token_remaps();
    let mut tokens = Vec::new();
    for (chain, bimap) in remaps.iter() {
        tokens.extend(bimap.left_values().map(|addr| Token::from_addr_on_chain(addr, *chain)));
    }
    tokens
}

/// Returns a read lock quard to the per-chain decimals map
pub fn read_token_decimals_map<'a>() -> RwLockReadGuard<'a, TokenDecimalsByChain> {
    DECIMALS_BY_CHAIN.read().expect("Decimals map lock poisoned")
}

/// Returns a read lock quard to the exchange support map
pub fn read_exchange_support<'a>() -> RwLockReadGuard<'a, ExchangeSupportMap> {
    EXCHANGE_SUPPORT_MAP.read().expect("Exchange support map lock poisoned")
}

/// Returns a write lock guard to the per-chain token remaps
pub fn write_token_remaps<'a>() -> RwLockWriteGuard<'a, TokenRemapsByChain> {
    TOKEN_REMAPS_BY_CHAIN.write().expect("Token remaps lock poisoned")
}

/// Returns a write lock quard to the per-chain decimals map
pub fn write_token_decimals_map<'a>() -> RwLockWriteGuard<'a, TokenDecimalsByChain> {
    DECIMALS_BY_CHAIN.write().expect("Decimals map lock poisoned")
}

/// Returns a write lock quard to the exchange support map
pub fn write_exchange_support<'a>() -> RwLockWriteGuard<'a, ExchangeSupportMap> {
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

/// Return the default Chain, or panic if none has ever been set
pub fn default_chain() -> Chain {
    // Fetch the default chain if it's configured
    let maybe_chain = DEFAULT_CHAIN.get().cloned();
    if let Some(chain) = maybe_chain {
        return chain;
    }

    // Otherwise, if only one chain is configured, use that
    let chains = read_token_remaps();
    assert!(chains.len() == 1, "No default chain configured, and multiple chains are configured");
    *chains.keys().next().expect("No chains configured")
}

/// Set the default chain in an idempotent manner
pub fn set_default_chain(chain: Chain) {
    DEFAULT_CHAIN.get_or_init(|| chain);
}
