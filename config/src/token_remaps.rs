//! Defines helpers for fetching or parsing a token remap
//!
//! See https://github.com/renegade-fi/token-mappings/tree/main for more information

use std::collections::HashMap;

use common::types::{
    chain::Chain,
    exchange::Exchange,
    token::{
        set_default_chain, write_exchange_support, write_token_decimals_map, write_token_remaps,
        USD_TICKER,
    },
};
use serde::{Deserialize, Serialize};
use util::raw_err_str;

/// The base URL for raw token remap files
const REMAP_BASE_URL: &str = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main/";

/// The zero address, used for the dummy "USD" token
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

// --------------------
// | Serialized Types |
// --------------------

/// The token remap type
///
/// Contains a series of token info objects
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TokenRemap {
    /// The token information in the remap file
    tokens: Vec<TokenInfo>,
}

/// The token info type
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    /// The name of the token
    name: String,
    /// The token's ticker
    ticker: String,
    /// The address of the token in the chain
    address: String,
    /// The number of decimals the token uses in the ERC20 representation
    decimals: u8,
    /// The exchanges that list the token, along with the ticker that we should
    /// use to fetch the token's price from the exchange
    supported_exchanges: HashMap<Exchange, String>,
    /// The canonical exchange from which to source the token's price
    canonical_exchange: Exchange,
}

impl TokenRemap {
    /// Set the static mapping of token addresses to tickers using the token
    /// mapping
    pub fn set_token_remap(&self, chain: Chain) {
        let mut all_maps = write_token_remaps();
        let token_remap = all_maps.entry(chain).or_default();

        // Clear the existing static token remapping so that it can be completely
        // overwritten
        token_remap.clear();

        for info in &self.tokens {
            token_remap.insert(info.address.clone(), info.ticker.clone());
        }

        // Insert a dummy token w/ the "USD" ticker so that we can fetch USD-quoted
        // prices from exchanges that support this.
        token_remap.insert(ZERO_ADDRESS.to_string(), USD_TICKER.to_string());
    }

    /// Set the static mapping of token addresses to decimals using the token
    /// mapping
    pub fn set_decimal_map(&self, chain: Chain) {
        let mut all_maps = write_token_decimals_map();
        let decimals_map = all_maps.entry(chain).or_default();

        // Clear the existing decimal mapping so that it can be completely overwritten
        decimals_map.clear();

        for info in &self.tokens {
            decimals_map.insert(info.address.clone(), info.decimals);
        }
    }

    /// Set the static exchange support mapping using the token mapping,
    /// The exchange support mapping maps token tickers to the set of
    /// exchanges that list the token, along with the ticker that we should use
    /// to fetch the token's price from the exchange
    pub fn set_exchange_support_map(&self) {
        let mut exchange_support_map = write_exchange_support();

        for info in &self.tokens {
            exchange_support_map.insert(info.ticker.clone(), info.supported_exchanges.clone());
        }

        // Insert exchange support for the dummy USD token
        let usd_ticker = USD_TICKER.to_string();
        exchange_support_map.insert(
            usd_ticker.clone(),
            [(Exchange::Coinbase, usd_ticker.clone()), (Exchange::Kraken, usd_ticker)]
                .into_iter()
                .collect(),
        );
    }

    /// Get the canonical exchange map from the token remap
    pub fn get_canonical_exchange_map(&self) -> HashMap<String, Exchange> {
        self.tokens.iter().map(|t| (t.ticker.clone(), t.canonical_exchange)).collect()
    }
}

/// Setup token remaps in the global `OnceCell`
pub fn setup_token_remaps(remap_file: Option<String>, chain: Chain) -> Result<(), String> {
    // If the remap file is not provided, fetch the Renegade maintained remap file
    // from the default location
    let mut map = if let Some(file) = remap_file {
        parse_remap_from_file(file)
    } else {
        fetch_remap_from_repo(chain)
    }?;
    lowercase_addresses(&mut map);

    // Update the static token remap with the given one
    map.set_token_remap(chain);

    // Update the static decimals map with the decimals in the token remap
    map.set_decimal_map(chain);

    // Update the static exchange support map with the supported exchanges
    // in the token remap
    map.set_exchange_support_map();

    // Set the default chain, if it has not already been set
    set_default_chain(chain);

    Ok(())
}

/// Lowercase all addresses in the remap
fn lowercase_addresses(remap: &mut TokenRemap) {
    for info in remap.tokens.iter_mut() {
        info.address = info.address.to_lowercase();
    }
}

/// Parse a token remap from a JSON file
pub fn parse_remap_from_file(file_path: String) -> Result<TokenRemap, String> {
    // Read the file into a string
    let file = std::fs::read_to_string(file_path)
        .map_err(raw_err_str!("Failed to read remap file: {}"))?;
    serde_json::from_str(&file).map_err(raw_err_str!("Failed to parse remap from file: {}"))
}

/// Pull the token remap from the repo
pub fn fetch_remap_from_repo(chain: Chain) -> Result<TokenRemap, String> {
    let url = format!("{}{}.json", REMAP_BASE_URL, chain);
    let resp =
        reqwest::blocking::get(url).map_err(raw_err_str!("Failed to fetch remap from repo: {}"))?;

    resp.json().map_err(raw_err_str!("Failed to parse remap from Github: {}"))
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, fs::File};

    use common::types::{chain::Chain, exchange::Exchange, token::read_token_remaps};
    use tempfile::{tempdir, TempDir};

    use crate::token_remaps::parse_remap_from_file;

    use super::{setup_token_remaps, TokenInfo, TokenRemap};

    /// Get a temporary dir and remap file for testing
    ///
    /// Returns the temp dir, file, and file path
    ///
    /// The file and dir must be returned so they are not dropped
    fn get_temp_dir() -> (TempDir, File, String) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("remap.json").to_str().unwrap().to_string();
        let file = File::create(&path).unwrap();

        (dir, file, path)
    }

    /// Get a dummy remap and save it to a file
    ///
    /// Returns both the remap and the file path
    ///
    /// The dir must be created in the calling scope to ensure it is not dropped
    fn gen_dummy_remap(file: &File) -> TokenRemap {
        let remap = TokenRemap {
            tokens: vec![TokenInfo {
                name: "Renegade".to_string(),
                ticker: "RNG".to_string(),
                address: "0x1234".to_string(),
                decimals: 18,
                supported_exchanges: HashMap::new(),
                canonical_exchange: Exchange::Renegade,
            }],
        };

        // Write the remap to the file
        serde_json::to_writer(file, &remap).unwrap();
        remap
    }

    /// Tests parsing the token remap from a file
    #[test]
    fn test_parse_token_remap() {
        let (_dir, file, path) = get_temp_dir();
        let remap = gen_dummy_remap(&file);

        // Parse the remap from the file
        let parsed = parse_remap_from_file(path).unwrap();
        assert_eq!(remap, parsed);
    }

    /// Tests that the token remap is correctly shared across threads
    #[test]
    fn test_token_remap_sharing() {
        let (_dir, file, path) = get_temp_dir();
        let remap = gen_dummy_remap(&file);

        // Setup the token remap
        setup_token_remaps(Some(path), Chain::Devnet).unwrap();
        let chain = Chain::Devnet;

        // Check the remap
        let token = &remap.tokens[0];
        let token_remaps = read_token_remaps();
        let chain_map = token_remaps.get(&chain).unwrap();
        assert_eq!(chain_map.get_by_left(&token.address), Some(&token.ticker));

        // Check the remap in a separate thread
        let handle = std::thread::spawn(move || {
            let token = &remap.tokens[0];
            let token_remaps = read_token_remaps();
            let chain_map = token_remaps.get(&chain).unwrap();
            assert_eq!(chain_map.get_by_left(&token.address), Some(&token.ticker));
        });
        handle.join().unwrap();
    }
}
