//! The Token is the cross-exchange abstraction of a fungible token. Since many different exchanges
//! define different standards for token names, tickers, etc., we use the Ethereum mainnet ERC-20
//! address as the authoritative identifier for each token. We map each of these contract addresses
//! into ticker names for consumption by each centralized exchange, as appropriate.
//!
//! Tokens fall under two different categories: "Named Tokens" that have centralized and
//! decentralized exchange price feed support, and "Unnamed Tokens" that only have decentralized
//! exchange price feed support. We explicitly name all Named Tokens below, as the relayer need to
//! manually map these ERC-20 addresses into websocket subscription requests.
//!
//! In general, Named Tokens use all exchanges where they are listed, whereas Unnamed Tokens only
//! use Uniswap V3 for the price feed.
use bimap::BiMap;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
};

use super::exchanges::{Exchange, ALL_EXCHANGES};

/// A helper enum to describe the state of each ticker on each Exchange. Same means that the ERC-20
/// and Exchange tickers are the same, Renamed means that the Exchange ticker is different from the
/// underlying ERC-20, and Unsupported  means that the asset is not supported on the Exchange.
#[derive(Clone, Copy, Debug)]
enum ExchangeTicker {
    /// The Exchange-native ticker is the same as the ERC-20 ticker.
    Same,
    /// The Exchange-native ticker is different from the ERC-20 ticker.
    Renamed(&'static str),
    /// The Exchange does not support this Token.
    Unsupported,
}

// We populate three global heap-allocated structs for convenience and metadata lookup. The first is
// a bidirectinal map between the ERC-20 contract address and the ERC-20 ticker. The second is a
// HashMap between the ERC-20 contract address and the number of decimals (fixed-point offset). The
// third is a HashMap between the ERC-20 ticker and each Exchange's expected name for each ticker.

/// The raw ERC-20 data to be parsed as heap-allocated global structs. The layout of ERC20_DATA is
/// (ERC-20 Address, Decimals, ERC-20 Ticker, Binance Ticker, Coinbase Ticker, Kraken Ticker, Okx
/// Ticker).
static ERC20_DATA: &[(
    &str,
    u8,
    &str,
    ExchangeTicker,
    ExchangeTicker,
    ExchangeTicker,
    ExchangeTicker,
)] = &[
    /* L1 */
    (
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
        8,
        "WBTC",
        ExchangeTicker::Renamed("BTC"),
        ExchangeTicker::Renamed("BTC"),
        ExchangeTicker::Renamed("BTC"),
        ExchangeTicker::Renamed("BTC"),
    ),
    (
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        18,
        "WETH",
        ExchangeTicker::Renamed("ETH"),
        ExchangeTicker::Renamed("ETH"),
        ExchangeTicker::Renamed("ETH"),
        ExchangeTicker::Renamed("ETH"),
    ),
    (
        "0xb8c77482e45f1f44de1745f52c74426c631bdd52",
        18,
        "BNB",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
    ),
    (
        "0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0",
        18,
        "MATIC",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x4e15361fd6b4bb609fa63c81a2be19d873717870",
        18,
        "FTM",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x6810e776880c02933d47db1b9fc05908e5386b96",
        18,
        "GNO",
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    /* LSDs */
    (
        "0xbe9895146f7af43049ca1c1ae358b0541ea49704",
        18,
        "CBETH",
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
    ),
    (
        "0x5a98fcbea516cf06857215779fd812ca3bef1b32",
        18,
        "LDO",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    /* Stables */
    (
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        6,
        "USDC",
        ExchangeTicker::Renamed("BUSD"),
        ExchangeTicker::Renamed("USD"),
        ExchangeTicker::Renamed("USD"),
        ExchangeTicker::Renamed("USDT"),
    ),
    (
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
        6,
        "USDT",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x4fabb145d64652a948d72533023f6e7a623c7c53",
        18,
        "BUSD",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
    ),
    /* Oracles */
    (
        "0xba11d00c5f74255f56a5e366f4f77f5a186d7f55",
        18,
        "BAND",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x514910771af9ca656af840dff83e8264ecf986ca",
        18,
        "LINK",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    /* DeFi Trading */
    (
        "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
        18,
        "UNI",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xd533a949740bb3306d119cc777fa900ba034cd52",
        18,
        "CRV",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x92d6c1e31e14520e676a687f0a93788b716beff5",
        18,
        "DYDX",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x6b3595068778dd592e39a122f4f5a5cf09c90fe2",
        18,
        "SUSHI",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x111111111117dc0aa78b770fa6a738034120c302",
        18,
        "1INCH",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xba100000625a3754423978a60c9317c58a424e3d",
        18,
        "BAL",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xb3999f658c0391d94a37f7ff328f3fec942bcadc",
        18,
        "HFT",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    (
        "0xbc396689893d065f41bc2c6ecbee5e0085233447",
        18,
        "PERP",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x4691937a7508860f876c9c0a2a617e7d9e945d4b",
        18,
        "WOO",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xe41d2489571d322189246dafa5ebde1f4699f498",
        18,
        "ZRX",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    /* DeFi Lending */
    (
        "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9",
        18,
        "AAVE",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xc00e94cb662c3520282e6f5717214004a7f26888",
        18,
        "COMP",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2",
        18,
        "MKR",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x0bc529c00c6401aef6d220be8c6ea1667f6ad93e",
        18,
        "YFI",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x090185f2135308bad17527004364ebcc2d37e5f6",
        18,
        "SPELL",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    /* DeFi Lending Undercollateralized */
    (
        "0x4c19596f5aaff459fa38b0f7ed92f11ae6543784",
        8,
        "TRU",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    (
        "0x33349b282065b0284d756f0577fb39c158f935e6",
        18,
        "MPL",
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
    ),
    /* DeFi Other */
    (
        "0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f",
        18,
        "SNX",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x221657776846890989a759ba2973e427dff5c9bb",
        18,
        "REP",
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x77777feddddffc19ff86db637967013e6c6a116c",
        18,
        "TORN",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
    ),
    /* Bridges */
    (
        "0x408e41876cccdc0f92210600ef50372656052a38",
        18,
        "REN",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xaf5191b0de278c7286d6c7cc6ab6bb8a73ba2cd6",
        18,
        "STG",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    (
        "0x4a220e6096b25eadb88358cb44068a3248254675",
        18,
        "QNT",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    /* L2s */
    (
        "0xbbbbca6a901c926f240b89eacb641d8aec7aeafd",
        18,
        "LRC",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x42bbfa2e77757c645eeaad1655e0911a7553efbc",
        18,
        "BOBA",
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    /* NFTs */
    (
        "0x4d224452801aced8b2f0aebe155379bb5d594381",
        18,
        "APE",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xbb0e17ef65f82ab018d8edd776e8dd940327b28b",
        18,
        "AXS",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xf629cbd94d3791c9250152bd8dfbdf380e2a3b9c",
        18,
        "ENJ",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xba5bde662c17e2adff1075610382b9b691296350",
        18,
        "RARE",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    /* Misc */
    (
        "0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce",
        18,
        "SHIB",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x7a58c0be72be218b41c608b7fe7c5bb630736c71",
        18,
        "PEOPLE",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
    ),
    (
        "0xd26114cd6ee289accf82350c8d8487fedb8a0c07",
        18,
        "OMG",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xc944e90c64b2c07662a292be6244bdf05cda44a7",
        18,
        "GRT",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0xc18360217d8f7ab5e7c516566761ea12ce7f9d72",
        18,
        "ENS",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x0f5d2fb29fb7d3cfee444a200298f468908cc942",
        18,
        "MANA",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x15d4c048f83bd7e37d49ea4c83a07267ec4203da",
        8,
        "GALA",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
    (
        "0x31c8eacbffdd875c74b94b077895bd78cf1e64a3",
        18,
        "RAD",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    (
        "0x18aaa7115705e8be94bffebde57af9bfc265b998",
        18,
        "AUDIO",
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
        ExchangeTicker::Same,
        ExchangeTicker::Unsupported,
    ),
    (
        "0x0d8775f648430679a709e98d2b0cb6250d2887ef",
        18,
        "BAT",
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
        ExchangeTicker::Same,
    ),
];

lazy_static! {
    static ref ADDR_TICKER_BIMAP: BiMap<String, String> = {
        let mut addr_ticker_bimap = BiMap::<String, String>::new();
        for (addr, _, ticker, _, _, _, _) in ERC20_DATA.iter() {
            addr_ticker_bimap.insert(String::from(*addr), String::from(*ticker));
        }
        addr_ticker_bimap
    };
    static ref ADDR_DECIMALS_MAP: HashMap<String, u8> = {
        let mut addr_decimals_map = HashMap::<String, u8>::new();
        for (addr, decimals, _, _, _, _, _) in ERC20_DATA.iter() {
            addr_decimals_map.insert(String::from(*addr), *decimals);
        }
        addr_decimals_map
    };
    static ref EXCHANGE_TICKERS: HashMap<Exchange, HashMap<String, String>> = {
        let mut exchange_tickers = HashMap::<Exchange, HashMap<String, String>>::new();
        for exchange in [
            Exchange::Binance,
            Exchange::Coinbase,
            Exchange::Kraken,
            Exchange::Okx,
        ] {
            exchange_tickers.insert(exchange, HashMap::<String, String>::new());
        }
        for (_, _, erc20_ticker, binance_ticker, coinbase_ticker, kraken_ticker, okx_ticker) in
            ERC20_DATA.iter()
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

/// The core Token abstraction, used for unambiguous definition of an ERC-20 asset.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Token {
    /// The ERC-20 address of the Token.
    addr: String,
}

impl Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl Token {
    /// Given an ERC-20 contract address, returns a new Token.
    pub fn _from_addr(addr: &str) -> Self {
        Self {
            addr: String::from(addr).to_lowercase(),
        }
    }

    /// Given an ERC-20 ticker, returns a new Token.
    pub fn from_ticker(ticker: &str) -> Self {
        let addr = ADDR_TICKER_BIMAP
            .get_by_right(&String::from(ticker))
            .expect("Ticker is not supported; specify unnamed token by ERC-20 address using from_addr instead.");
        Self {
            addr: addr.to_string(),
        }
    }

    /// Returns the ERC-20 address.
    pub fn get_addr(&self) -> &str {
        &self.addr
    }

    /// Returns the ERC-20 ticker, if available. Note that it is OK if certain Tickers do not have
    /// any ERC-20 ticker, as we support long-tail assets.
    pub fn get_ticker(&self) -> Option<&str> {
        ADDR_TICKER_BIMAP
            .get_by_left(&self.addr)
            .map(|ticker| &**ticker)
    }

    /// Returns the ERC-20 `decimals` field, if available.
    pub fn get_decimals(&self) -> Option<u8> {
        ADDR_DECIMALS_MAP.get(self.get_addr()).copied()
    }

    /// Returns true if the Token has a Renegade-native ticker.
    pub fn is_named(&self) -> bool {
        self.get_ticker().is_some()
    }

    /// Returns the set of Exchanges that support this token.
    pub fn supported_exchanges(&self) -> HashSet<Exchange> {
        let mut supported_exchanges = HashSet::<Exchange>::new();
        supported_exchanges.insert(Exchange::UniswapV3);
        if !self.is_named() {
            return supported_exchanges;
        }
        for exchange in ALL_EXCHANGES.iter() {
            if *exchange == Exchange::UniswapV3 {
                continue;
            }
            if EXCHANGE_TICKERS
                .get(exchange)
                .unwrap()
                .get(self.get_ticker().unwrap())
                .is_some()
            {
                supported_exchanges.insert(*exchange);
            }
        }
        supported_exchanges
    }

    /// Returns the ticker, in accordance with what each Exchange expects. This requires
    /// hard-coding and manual lookup, since CEXes typically do not support indexing by ERC-20
    /// address. If the ticker is not supported by the Exchange, returns None.
    pub fn get_exchange_ticker(&self, exchange: Exchange) -> String {
        // If there is not a Renegade-native ticker, then the token must be Unnamed.
        if !self.is_named() {
            panic!(
                "Tried to get_exchange_ticker({}) for an unnamed Token.",
                exchange
            );
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
}
