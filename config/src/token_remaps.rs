//! Defines helpers for fetching or parsing a token remap
//!
//! See https://github.com/renegade-fi/token-mappings/tree/main for more information

use arbitrum_client::constants::Chain;
use serde::Deserialize;
use util::raw_err_str;

// --------------------
// | Serialized Types |
// --------------------

/// The token remap type
///
/// Contains a series of token info objects
#[derive(Deserialize, Debug)]
struct TokenRemap {
    /// The token information in the remap file
    tokens: Vec<TokenInfo>,
}

/// The token info type
#[derive(Deserialize, Debug)]
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

/// The base URL for raw token remap files
const REMAP_BASE_URL: &str = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main/";

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
    println!("map: {map:?}");

    Ok(())
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
    println!("url: {url}");
    let resp = reqwest::blocking::get(&url)
        .map_err(raw_err_str!("Failed to fetch remap from repo: {}"))?;

    resp.json().map_err(raw_err_str!("Failed to parse remap from Github: {}"))
}
