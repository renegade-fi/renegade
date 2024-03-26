//! Defines helpers for fetching or parsing a token remap
//!
//! See https://github.com/renegade-fi/token-mappings/tree/main for more information

use std::collections::HashMap;

use arbitrum_client::constants::Chain;
use bimap::BiMap;
use common::types::token::{ADDR_DECIMALS_MAP, TOKEN_REMAPS};
use serde::{Deserialize, Serialize};
use tracing::warn;
use util::raw_err_str;

/// The base URL for raw token remap files
const REMAP_BASE_URL: &str = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main/";

// --------------------
// | Serialized Types |
// --------------------

/// The token remap type
///
/// Contains a series of token info objects
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct TokenRemap {
    /// The token information in the remap file
    tokens: Vec<TokenInfo>,
}

/// The token info type
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct TokenInfo {
    /// The name of the token
    name: String,
    /// The token's ticker
    ticker: String,
    /// The address of the token in the chain
    address: String,
    /// The number of decimals the token uses in the ERC20 representation
    decimals: u8,
}

impl TokenRemap {
    /// Convert the token mapping into a map of token addresses to ticker
    pub fn to_remap(&self) -> BiMap<String, String> {
        self.tokens.iter().map(|info| (info.address.clone(), info.ticker.clone())).collect()
    }

    /// Convert the token mapping into a map of token addresses to decimals
    pub fn to_decimal_map(&self) -> HashMap<String, u8> {
        self.tokens.iter().map(|info| (info.address.clone(), info.decimals)).collect()
    }
}

/// Setup token remaps in the global `OnceCell`
pub fn setup_token_remaps(remap_file: Option<String>, chain: Chain) -> Result<(), String> {
    // If the remap file is not provided, fetch the Renegade maintained remap file
    // from the default location
    let map = if let Some(file) = remap_file {
        parse_remap_from_file(file)
    } else {
        fetch_remap_from_repo(chain)
    }?;

    // Update the static token remap with the given one
    let remap = map.to_remap();
    match TOKEN_REMAPS.get() {
        Some(_) => {
            warn!("Token remap already set, cannot override");
        },
        None => TOKEN_REMAPS.set(remap).map_err(raw_err_str!("Failed to set token remap: {:?}"))?,
    };

    // Update the static decimals map with the decimals in the token remap
    let decimals_map = map.to_decimal_map();
    match ADDR_DECIMALS_MAP.get() {
        Some(_) => {
            warn!("Token decimals map already set, cannot override");
            Ok(())
        },
        None => ADDR_DECIMALS_MAP
            .set(decimals_map)
            .map_err(raw_err_str!("Failed to set token decimals map: {:?}")),
    }
}

/// Parse a token remap from a JSON file
fn parse_remap_from_file(file_path: String) -> Result<TokenRemap, String> {
    // Read the file into a string
    let file = std::fs::read_to_string(file_path)
        .map_err(raw_err_str!("Failed to read remap file: {}"))?;
    serde_json::from_str(&file).map_err(raw_err_str!("Failed to parse remap from file: {}"))
}

/// Pull the token remap from the repo
fn fetch_remap_from_repo(chain: Chain) -> Result<TokenRemap, String> {
    let url = format!("{}{}.json", REMAP_BASE_URL, chain);
    let resp =
        reqwest::blocking::get(url).map_err(raw_err_str!("Failed to fetch remap from repo: {}"))?;

    resp.json().map_err(raw_err_str!("Failed to parse remap from Github: {}"))
}

#[cfg(test)]
mod test {
    use std::fs::File;

    use arbitrum_client::constants::Chain;
    use common::types::token::TOKEN_REMAPS;
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

        // Check the remap
        let token = &remap.tokens[0];
        assert_eq!(TOKEN_REMAPS.get().unwrap().get_by_left(&token.address), Some(&token.ticker));

        // Check the remap in a separate thread
        let handle = std::thread::spawn(move || {
            let token = &remap.tokens[0];
            assert_eq!(
                TOKEN_REMAPS.get().unwrap().get_by_left(&token.address),
                Some(&token.ticker)
            );
        });
        handle.join().unwrap();
    }
}
