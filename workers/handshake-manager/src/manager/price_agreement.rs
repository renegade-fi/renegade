//! Groups logic for sampling and agreeing upon price vectors during a handshake

use std::collections::HashMap;

use common::types::{exchange::PriceReporterState, token::Token, wallet::OrderIdentifier, Price};
use gossip_api::request_response::handshake::PriceVector;
use job_types::price_reporter::{PriceReporterJob, PriceReporterQueue};
use lazy_static::lazy_static;
use tokio::sync::oneshot;
use tracing::{error, instrument, warn};

use super::{HandshakeExecutor, HandshakeManagerError};

/// The maximum percentage deviation that is allowed between a peer's proposed
/// price and a locally observed price before the proposed price is rejected
const MAX_PRICE_DEVIATION: f64 = 0.01;
/// Error message emitted when price data could not be found for a given token
/// pair
const ERR_NO_PRICE_STREAM: &str = "price report not available for token pair";

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
    pub static ref DEFAULT_PAIRS: Vec<(Token, Token)> = {
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

/// Initializes price streams for the default token pairs in the
/// `price-reporter`
///
/// This will cause the price reporter to connect to exchanges and begin
/// streaming, ahead of when we need prices
#[allow(clippy::needless_pass_by_value)]
#[instrument(skip_all, err)]
pub fn init_price_streams(
    price_reporter_job_queue: PriceReporterQueue,
) -> Result<(), HandshakeManagerError> {
    for (base, quote) in DEFAULT_PAIRS.iter() {
        price_reporter_job_queue
            .send(PriceReporterJob::StartPriceReporter {
                base_token: base.clone(),
                quote_token: quote.clone(),
            })
            .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;
    }

    Ok(())
}

impl HandshakeExecutor {
    /// Fetch a price vector from the price reporter
    pub(super) async fn fetch_price_vector(&self) -> Result<PriceVector, HandshakeManagerError> {
        // Enqueue jobs in the price manager to snapshot the midpoint for each pair
        let mut channels = Vec::with_capacity(DEFAULT_PAIRS.len());
        for (base, quote) in DEFAULT_PAIRS.iter().cloned() {
            let (sender, receiver) = oneshot::channel();
            self.price_reporter_job_queue
                .send(PriceReporterJob::PeekMedian {
                    base_token: base,
                    quote_token: quote,
                    channel: sender,
                })
                .map_err(|err| HandshakeManagerError::SetupError(err.to_string()))?;
            channels.push(receiver);
        }

        // Wait for the price reporter to respond with the midpoint prices for each pair
        let mut midpoint_prices = Vec::new();
        for response_channel in channels.into_iter() {
            let res = response_channel.await;
            if res.is_err() {
                error!("Error fetching price vector: {res:?}");
                continue;
            }
            let midpoint_state = res.unwrap();

            match midpoint_state {
                PriceReporterState::Nominal(report) => {
                    midpoint_prices.push((
                        report.base_token,
                        report.quote_token,
                        report.midpoint_price,
                    ));
                },

                // TODO: We may want to re-evaluate whether we want to accept price reports
                // with large deviation. This largely happens because of Uniswap, and we could
                // implement a more complex deviation calculation that ignores DEXs
                PriceReporterState::TooMuchDeviation(report, _) => {
                    midpoint_prices.push((
                        report.base_token,
                        report.quote_token,
                        report.midpoint_price,
                    ));
                },

                err_state => {
                    warn!("Price report invalid during price agreement: {err_state:?}");
                },
            }
        }

        Ok(PriceVector(midpoint_prices))
    }

    /// Validate a price vector against an order we intend to match
    ///
    /// The input prices are those proposed by a peer that has initiated a match
    /// against a locally managed order
    ///
    /// The result is `None` if the prices are rejected. If the prices are
    /// accepted the result is the midpoint price of the asset pair that the
    /// local party's order is on
    pub(super) async fn validate_price_vector(
        &self,
        proposed_prices: &PriceVector,
        my_order_id: &OrderIdentifier,
    ) -> Result<bool, HandshakeManagerError> {
        // Find the price of the asset pair that the local party's order is on in the
        // peer's proposed prices list
        let (base, quote) = self.token_pair_for_order(my_order_id)?;
        let proposed_price = proposed_prices.find_pair(&base, &quote);
        if proposed_price.is_none() {
            return Ok(false);
        }

        // Validate that the maximum deviation between the proposed prices and the
        // locally observed prices is within the acceptable range
        let my_prices: HashMap<(Token, Token), Price> = self.fetch_price_vector().await?.into();
        let peer_prices: HashMap<(Token, Token), Price> = proposed_prices.clone().into();
        if !my_prices.contains_key(&(base.clone(), quote.clone())) {
            return Err(HandshakeManagerError::NoPriceData(format!(
                "{ERR_NO_PRICE_STREAM}: {base}-{quote}"
            )));
        }

        // We cannot simply validate that the peer's proposed price for *our asset pair*
        // is within the acceptable range. This behavior would allow the peer to probe
        // price rejections with different assets to determine the asset pair an
        // order is on So instead we validate all of the peer's proposed prices
        // that we have local prices for
        for ((base, quote), peer_price) in peer_prices.into_iter() {
            if let Some(my_price) = my_prices.get(&(base, quote)) {
                let price_deviation = (peer_price - my_price) / my_price;
                if price_deviation.abs() > MAX_PRICE_DEVIATION {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}
