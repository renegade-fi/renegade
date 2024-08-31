//! Groups logic for sampling and agreeing upon price vectors during a handshake

use std::collections::HashMap;

use common::types::{
    exchange::PriceReporterState,
    token::{Token, TOKEN_REMAPS, USDC_TICKER},
    wallet::OrderIdentifier,
    TimestampedPrice,
};
use gossip_api::request_response::handshake::PriceVector;
use job_types::price_reporter::{PriceReporterJob, PriceReporterQueue};
use tokio::sync::oneshot::{self, Receiver};
use tracing::{error, instrument, warn};
use util::err_str;

use super::{HandshakeExecutor, HandshakeManagerError};

/// The maximum percentage deviation that is allowed between a peer's proposed
/// price and a locally observed price before the proposed price is rejected
const MAX_PRICE_DEVIATION: f64 = 0.01;
/// Error message emitted when price data could not be found for a given token
/// pair
const ERR_NO_PRICE_STREAM: &str = "price report not available for token pair";

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
    let quote = Token::from_ticker(USDC_TICKER);

    for (addr, _) in TOKEN_REMAPS.get().unwrap().iter() {
        let base = Token::from_addr(addr);
        if base == quote {
            // Skip the USDC-USDC pair
            continue;
        }

        price_reporter_job_queue
            .send(PriceReporterJob::StreamPrice {
                base_token: base.clone(),
                quote_token: quote.clone(),
            })
            .map_err(err_str!(HandshakeManagerError::PriceReporter))?;
    }

    Ok(())
}

impl HandshakeExecutor {
    /// Fetch a price vector from the price reporter
    pub(super) async fn fetch_price_vector(&self) -> Result<PriceVector, HandshakeManagerError> {
        // Enqueue jobs in the price manager to snapshot the midpoint for each pair
        let token_maps = TOKEN_REMAPS.get().unwrap();
        let quote = Token::from_ticker(USDC_TICKER);

        let mut channels = Vec::with_capacity(token_maps.len());
        for (base_addr, _ticker) in token_maps.iter() {
            let base = Token::from_addr(base_addr);
            let receiver = self.request_price(base, quote.clone())?;
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
                    let price = (&report).into();
                    midpoint_prices.push((report.base_token, report.quote_token, price));
                },

                // TODO: We may want to re-evaluate whether we want to accept price reports
                // with large deviation. This largely happens because of Uniswap, and we could
                // implement a more complex deviation calculation that ignores DEXs
                PriceReporterState::TooMuchDeviation(report, _) => {
                    let price = (&report).into();
                    midpoint_prices.push((report.base_token, report.quote_token, price));
                },

                err_state => {
                    warn!("Price report invalid during price agreement: {err_state:?}");
                },
            }
        }

        Ok(PriceVector(midpoint_prices))
    }

    /// Requests a price from the price reporter, returning a channel upon which
    /// the price will be received
    pub(super) fn request_price(
        &self,
        base_token: Token,
        quote_token: Token,
    ) -> Result<Receiver<PriceReporterState>, HandshakeManagerError> {
        let (sender, receiver) = oneshot::channel();
        self.price_reporter_job_queue
            .send(PriceReporterJob::PeekPrice { base_token, quote_token, channel: sender })
            .map_err(err_str!(HandshakeManagerError::PriceReporter))?;
        Ok(receiver)
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
        let (base, quote) = self.token_pair_for_order(my_order_id).await?;
        let proposed_price = proposed_prices.find_pair(&base, &quote);
        if proposed_price.is_none() {
            return Ok(false);
        }

        // Validate that the maximum deviation between the proposed prices and the
        // locally observed prices is within the acceptable range
        let my_prices: HashMap<(Token, Token), TimestampedPrice> =
            self.fetch_price_vector().await?.into();
        let peer_prices: HashMap<(Token, Token), TimestampedPrice> = proposed_prices.clone().into();
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
        for ((base, quote), TimestampedPrice { price: peer_price, .. }) in peer_prices.into_iter() {
            if let Some(TimestampedPrice { price: my_price, .. }) = my_prices.get(&(base, quote)) {
                let price_deviation = (peer_price - my_price) / my_price;
                if price_deviation.abs() > MAX_PRICE_DEVIATION {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}
