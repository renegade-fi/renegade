//! A token bound to a specific Chain, scoping chain-specific operations.
use super::chain::Chain;
use super::exchange::Exchange;
use super::token::{
    read_exchange_support, read_token_decimals_map, read_token_remaps, Token, USDT_TICKER,
    USD_TICKER,
};
use std::collections::HashSet;
use std::ops::Deref;

/// The `ChainToken` type is used to provide a `Token` wrapper that is bound to
/// a specific `Chain`, allowing for chain-specific operations.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ChainToken {
    /// The chain this token is bound to.
    pub chain: Chain,
    /// The underlying Token.
    pub token: Token,
}

impl ChainToken {
    /// Given an ERC-20 contract address and a chain, returns a new `ChainToken`
    pub fn from_addr_on(chain: Chain, addr: &str) -> Self {
        Self { chain, token: Token::from_addr(addr) }
    }

    /// Given an ERC-20 ticker and a chain, return a `ChainToken` for the
    /// token on the given chain.
    pub fn from_ticker_on(chain: Chain, ticker: &str) -> Self {
        let remaps = read_token_remaps();
        let bimap = remaps.get(&chain).expect("chain not in remaps");
        let addr = bimap.get_by_right(ticker).expect("ticker not in chain remap").to_string();
        Self { chain, token: Token { addr } }
    }

    /// Given an ERC-20 ticker, return a new `ChainToken` This will return the
    /// first address found for the ticker.
    ///
    /// Panics if the ticker is not found in any chain remaps.
    pub fn from_ticker(ticker: &str) -> Self {
        let remaps = read_token_remaps();
        for (chain, bimap) in remaps.iter() {
            if let Some(addr) = bimap.get_by_right(ticker) {
                return Self::from_addr_on(*chain, addr);
            }
        }
        panic!("ticker not found in any chain remaps: {}", ticker);
    }

    /// Returns the ERC-20 ticker, if available. Note that it is OK if certain
    /// Tickers do not have any ERC-20 ticker, as we support long-tail
    /// assets.
    pub fn get_ticker(&self) -> Option<String> {
        read_token_remaps()
            .get(&self.chain)
            .and_then(|bimap| bimap.get_by_left(&self.token.get_addr()).cloned())
    }

    /// Returns the ERC-20 `decimals` field, if available.
    pub fn get_decimals(&self) -> Option<u8> {
        read_token_decimals_map()
            .get(&self.chain)
            .and_then(|m| m.get(&self.token.get_addr()).copied())
    }

    /// Returns true if the Token has a Renegade-native ticker.
    pub fn is_named(&self) -> bool {
        self.get_ticker().is_some()
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

    // TODO: override all methods that use self. in Token
}

// -----------
// | HELPERS |
// -----------

/// Default stable quote asset for an exchange on this chain.
pub fn default_exchange_stable(chain: Chain, exchange: &Exchange) -> ChainToken {
    let ticker = match exchange {
        Exchange::Binance => USDT_TICKER,
        Exchange::Coinbase => USD_TICKER,
        Exchange::Kraken => USD_TICKER,
        Exchange::Okx => USDT_TICKER,
        _ => panic!("No default stable quote asset for exchange: {:?}", exchange),
    };
    ChainToken::from_ticker_on(chain, ticker)
}

/// Returns all tokens for the given chain, or for all chains if `None`.
pub fn get_all_tokens(chain: Option<Chain>) -> Vec<ChainToken> {
    let remaps = read_token_remaps();
    let mut tokens = Vec::new();
    if let Some(chain) = chain {
        if let Some(bimap) = remaps.get(&chain) {
            tokens.extend(bimap.left_values().map(|addr| ChainToken::from_addr_on(chain, addr)));
        }
    } else {
        for (&chain_key, bimap) in remaps.iter() {
            tokens
                .extend(bimap.left_values().map(|addr| ChainToken::from_addr_on(chain_key, addr)));
        }
    }
    tokens
}

impl Deref for ChainToken {
    type Target = Token;
    fn deref(&self) -> &Token {
        &self.token
    }
}

impl From<(Chain, Token)> for ChainToken {
    fn from((chain, token): (Chain, Token)) -> Self {
        ChainToken { chain, token }
    }
}

impl Clone for ChainToken {
    fn clone(&self) -> Self {
        ChainToken {
            chain: self.chain,         // Copy or clone as needed
            token: self.token.clone(), // calls Token::clone()
        }
    }
}
