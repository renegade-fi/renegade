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
use std::collections::HashMap;

// We populate two global heap-allocated structs for convenience and metadata lookup. The first is
// a bidirectinal map between the ERC-20 contract address and the ERC-20 ticker. The second is a
// HashMap between the ERC-20 contract address and the number of decimals (fixed-point offset).
static TOKEN_DATA: &[(&str, u8, &str)] = &[
    /* L1 */
    ("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", 18, "WETH"),
    ("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", 8, "WBTC"),
    ("0xb8c77482e45f1f44de1745f52c74426c631bdd52", 18, "BNB"),
    ("0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0", 18, "MATIC"),
    ("0x6810e776880c02933d47db1b9fc05908e5386b96", 18, "GNO"),
    ("0xe28b3b32b6c345a34ff64674606124dd5aceca30", 18, "INJ"),
    ("0x85f17cf997934a597031b2e18a9ab6ebd4b9f6a4", 24, "NEAR"),
    /* LSDs */
    ("0xbe9895146f7af43049ca1c1ae358b0541ea49704", 18, "CBETH"),
    ("0x5a98fcbea516cf06857215779fd812ca3bef1b32", 18, "LDO"),
    /* Stables */
    ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, "USDC"),
    ("0xdac17f958d2ee523a2206206994597c13d831ec7", 6, "USDT"),
    ("0x4fabb145d64652a948d72533023f6e7a623c7c53", 18, "BUSD"),
    ("0x6b175474e89094c44da98b954eedeac495271d0f", 18, "DAI"),
    ("0x956f47f50a910163d8bf957cf5846d573e7f87ca", 18, "FEI"),
    ("0x853d955acef822db058eb8505911ed77f175b99e", 18, "FRAX"),
    ("0xd46ba6d942050d489dbd938a2c909a5d5039a161", 9, "AMPL"),
    /* Oracles */
    ("0xba11d00c5f74255f56a5e366f4f77f5a186d7f55", 18, "BAND"),
    ("0x514910771af9ca656af840dff83e8264ecf986ca", 18, "LINK"),
    /* DeFi Trading */
    ("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", 18, "UNI"),
    ("0xd533a949740bb3306d119cc777fa900ba034cd52", 18, "CRV"),
    ("0x6b3595068778dd592e39a122f4f5a5cf09c90fe2", 18, "SUSHI"),
    ("0x111111111117dc0aa78b770fa6a738034120c302", 18, "1INCH"),
    ("0xba100000625a3754423978a60c9317c58a424e3d", 18, "BAL"),
    ("0xbc396689893d065f41bc2c6ecbee5e0085233447", 18, "PERP"),
    ("0x4691937a7508860f876c9c0a2a617e7d9e945d4b", 18, "WOO"),
    ("0xe41d2489571d322189246dafa5ebde1f4699f498", 18, "ZRX"),
    /* DeFi Lending */
    ("0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9", 18, "AAVE"),
    ("0xc00e94cb662c3520282e6f5717214004a7f26888", 18, "COMP"),
    ("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2", 18, "MKR"),
    ("0x0bc529c00c6401aef6d220be8c6ea1667f6ad93e", 18, "YFI"),
    ("0x2ba592f78db6436527729929aaf6c908497cb200", 18, "CREAM"),
    /* DeFi Lending Undercollateralized */
    ("0x4c19596f5aaff459fa38b0f7ed92f11ae6543784", 8, "TRU"),
    ("0x33349b282065b0284d756f0577fb39c158f935e6", 18, "MPL"),
    /* DeFi Other */
    ("0x64aa3364f17a4d01c6f1751fd97c2bd3d7e7f1d5", 9, "OHM"),
    ("0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f", 18, "SNX"),
    ("0x0cec1a9154ff802e7934fc916ed7ca50bde6844e", 18, "POOL"),
    ("0x221657776846890989a759ba2973e427dff5c9bb", 18, "REP"),
    ("0x1494ca1f11d487c2bbe4543e90080aeba4ba3c2b", 18, "DPI"),
    ("0x77777feddddffc19ff86db637967013e6c6a116c", 18, "TORN"),
    /* Bridges */
    ("0x408e41876cccdc0f92210600ef50372656052a38", 18, "REN"),
    ("0xaf5191b0de278c7286d6c7cc6ab6bb8a73ba2cd6", 18, "STG"),
    /* L2s */
    ("0xbbbbca6a901c926f240b89eacb641d8aec7aeafd", 18, "LRC"),
    ("0x42bbfa2e77757c645eeaad1655e0911a7553efbc", 18, "BOBA"),
    /* NFTs */
    ("0x1e4ede388cbc9f4b5c79681b7f94d36a11abebc9", 18, "X2Y2"),
    ("0x4d224452801aced8b2f0aebe155379bb5d594381", 18, "APE"),
    ("0xf4d2888d29d722226fafa5d9b24f9164c092421e", 18, "LOOKS"),
    /* Misc */
    ("0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce", 18, "SHIB"),
    ("0xd26114cd6ee289accf82350c8d8487fedb8a0c07", 18, "OMG"),
    ("0xc944e90c64b2c07662a292be6244bdf05cda44a7", 18, "GRT"),
    ("0xc18360217d8f7ab5e7c516566761ea12ce7f9d72", 18, "ENS"),
    ("0x85eee30c52b0b379b046fb0f85f4f3dc3009afec", 18, "KEEP"),
    ("0x0f5d2fb29fb7d3cfee444a200298f468908cc942", 18, "MANA"),
    ("0xaaaebe6fe48e54f431b0c390cfaf0b017d09d42d", 4, "CEL"),
    ("0x4fe83213d56308330ec302a8bd641f1d0113a4cc", 18, "NU"),
    ("0x18aaa7115705e8be94bffebde57af9bfc265b998", 18, "AUDIO"),
    ("0x0d8775f648430679a709e98d2b0cb6250d2887ef", 18, "BAT"),
];
lazy_static! {
    static ref ADDR_TICKER_BIMAP: BiMap<String, String> = {
        let mut addr_ticker_bimap = BiMap::<String, String>::new();
        for (addr, _decimals, ticker) in TOKEN_DATA.iter() {
            addr_ticker_bimap.insert(String::from(*addr), String::from(*ticker));
        }
        addr_ticker_bimap
    };
    static ref ADDR_DECIMALS_MAP: HashMap<String, u8> = {
        let mut addr_decimals_map = HashMap::<String, u8>::new();
        for (addr, decimals, _ticker) in TOKEN_DATA.iter() {
            addr_decimals_map.insert(String::from(*addr), *decimals);
        }
        addr_decimals_map
    };
}

#[derive(Clone, Debug)]
pub struct Token {
    /// The ERC-20 address of the Token.
    addr: String,
}
impl Token {
    /// Given an ERC-20 contract address, returns a new Token.
    pub fn from_addr(addr: &str) -> Self {
        Self {
            addr: String::from(addr),
        }
    }

    /// Given a Renegade-native ticker, returns a new Token.
    pub fn from_ticker(ticker: &str) -> Self {
        // TODO: More gracefully fail if a user does not supply a valid ticker.
        let addr = ADDR_TICKER_BIMAP.get_by_right(&String::from(ticker)).unwrap();
        Self {
            addr: addr.to_string(),
        }
    }

    pub fn get_addr(&self) -> &str {
        &self.addr
    }

    /// Returns the Renegade-native ticker, if available. Note that it is OK if certain Tickers do
    /// not have any Renegade-native ticker, as we support long-tail assets.
    pub fn get_ticker(&self) -> Option<&str> {
        ADDR_TICKER_BIMAP
            .get_by_left(&self.addr)
            .map(|ticker| &**ticker)
    }

    pub fn get_decimals(&self) -> Option<u8> {
        ADDR_DECIMALS_MAP.get(self.get_addr()).map(|decimals| *decimals)
    }

    /// Returns true if the Token has a Renegade-native ticker.
    pub fn is_named(&self) -> bool {
        self.get_ticker().is_some()
    }
}
