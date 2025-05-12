//! Chain-specific Token methods
use num_bigint::BigUint;
use util::hex::biguint_to_hex_addr;

use super::{
    chain::Chain,
    token::{read_token_remaps, Token},
};

impl Token {
    /// Given an ERC-20 contract address, returns a new Token on a specific
    /// chain.
    pub fn from_addr_on_chain(addr: &str, chain: Chain) -> Self {
        Self { addr: String::from(addr).to_lowercase(), chain }
    }

    /// Given an ERC-20 contract address represented as a `BigUint`, returns a
    /// Token
    pub fn from_addr_biguint_on_chain(addr: &BigUint, chain: Chain) -> Self {
        Self { addr: biguint_to_hex_addr(addr).to_lowercase(), chain }
    }

    /// Given an ERC-20 contract address, returns a new Token, if available.
    pub fn from_addr_without_chain(addr: &str) -> Option<Self> {
        let addr = String::from(addr).to_lowercase();
        for (chain, token_map) in read_token_remaps().iter() {
            if token_map.get_by_left(&addr).is_some() {
                return Some(Self { addr, chain: *chain });
            }
        }
        None
    }

    /// Given an ERC-20 ticker, returns a new Token on a specific chain.
    pub fn from_ticker_on_chain(ticker: &str, chain: Chain) -> Self {
        let all_maps = read_token_remaps();
        let token_map = all_maps.get(&chain).expect("Chain has not been setup");
        let addr = token_map.get_by_right(ticker).expect("Ticker could not be found on chain");
        Self { addr: addr.to_string(), chain }
    }

    /// Returns the chain the token is on.
    pub fn get_chain(&self) -> Chain {
        self.chain
    }
}
