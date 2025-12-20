//! Groups logic for sampling and agreeing upon price vectors during a handshake

use std::collections::HashMap;

use common::types::{
    exchange::PriceReporterState,
    price::TimestampedPrice,
    token::{Token, get_all_base_tokens},
    wallet::OrderIdentifier,
};
use gossip_api::request_response::handshake::PriceVector;
use tracing::warn;
use util::err_str;

use super::{HandshakeExecutor, HandshakeManagerError};

/// The maximum percentage deviation that is allowed between a peer's proposed
/// price and a locally observed price before the proposed price is rejected
const MAX_PRICE_DEVIATION: f64 = 0.01;
/// Error message emitted when price data could not be found for a given token
/// pair
const ERR_NO_PRICE_STREAM: &str = "price report not available for token pair";

impl HandshakeExecutor {
    /// Fetch a price vector from the price reporter
    pub(super) fn fetch_price_vector(&self) -> Result<PriceVector, HandshakeManagerError> {
        // Get the price state for each base token
        let quote = Token::usdc();
        let mut midpoint_prices = Vec::new();
        for base in get_all_base_tokens() {
            let state = self.price_streams.get_state(&base, &quote);

            match state {
                // TODO: We may want to re-evaluate whether we want to accept price reports
                // with large deviation when MPC matches are live
                PriceReporterState::Nominal(report)
                | PriceReporterState::TooMuchDeviation(report, _) => {
                    let price: TimestampedPrice = (&report).into();
                    let corrected_price = price
                        .get_decimal_corrected_price(&report.base_token, &report.quote_token)
                        .map_err(err_str!(HandshakeManagerError::NoPriceData))?;
                    midpoint_prices.push((report.base_token, report.quote_token, corrected_price));
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
        let (base, quote) = self.token_pair_for_order(my_order_id).await?;
        let proposed_price = proposed_prices.find_pair(&base, &quote);
        if proposed_price.is_none() {
            return Ok(false);
        }

        // Validate that the maximum deviation between the proposed prices and the
        // locally observed prices is within the acceptable range
        let my_prices: HashMap<(Token, Token), TimestampedPrice> =
            self.fetch_price_vector()?.into();
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
