//! Groups logic for sampling and agreeing upon price vectors during a handshake

use lazy_static::lazy_static;
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::{
    handshake::error::HandshakeManagerError,
    price_reporter::{jobs::PriceReporterManagerJob, tokens::Token},
};

// ----------------
// | Quote Tokens |
// ----------------

/// USDC ticker
///
/// For now we only stream prices quoted in USDC
const USDC_TICKER: &str = "USDC";

// ---------------
// | Base Tokens |
// ---------------

/// BTC ticker
const BTC_TICKER: &str = "WBTC";
/// ETH ticker
const ETH_TICKER: &str = "WETH";
/// BNB ticker
const BNB_TICKER: &str = "BNB";
/// MATIC ticker
const MATIC_TICKER: &str = "MATIC";
/// LDO ticker
const LDO_TICKER: &str = "LDO";
/// CBETH ticker
const CBETH_TICKER: &str = "CBETH";
/// LINK ticker
const LINK_TICKER: &str = "LINK";
/// UNI ticker
const UNI_TICKER: &str = "UNI";
/// CRV ticker
const CRV_TICKER: &str = "CRV";
/// DYDX ticker
const DYDX_TICKER: &str = "DYDX";
/// AAVE ticker
const AAVE_TICKER: &str = "AAVE";

lazy_static! {
    /// The token pairs we want to keep price streams open for persistently
    static ref DEFAULT_PAIRS: Vec<(Token, Token)> = {
        // For now we only stream prices quoted in USDC
        vec![
            (
                Token::from_ticker(BTC_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(ETH_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(BNB_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(MATIC_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(LDO_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(CBETH_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(LINK_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(UNI_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(CRV_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(DYDX_TICKER),
                Token::from_ticker(USDC_TICKER),
            ),
            (
                Token::from_ticker(AAVE_TICKER),
                Token::from_ticker(USDC_TICKER),
            )
        ]
    };
}

/// Initializes price streams for the default token pairs in the `price-reporter`
///
/// This will cause the price reporter to connect to exchanges and begin streaming, ahead of
/// when we need prices
pub fn init_price_streams(
    price_reporter_job_queue: TokioSender<PriceReporterManagerJob>,
) -> Result<(), HandshakeManagerError> {
    for (base, quote) in DEFAULT_PAIRS.iter() {
        price_reporter_job_queue
            .send(PriceReporterManagerJob::StartPriceReporter {
                base_token: base.clone(),
                quote_token: quote.clone(),
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;
    }

    Ok(())
}
