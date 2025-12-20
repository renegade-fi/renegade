//! Utilities for the PriceReporter manager

use std::collections::HashSet;

use common::types::{
    exchange::Exchange,
    token::{Token, default_exchange_stable, get_all_base_tokens},
};
use itertools::Itertools;
use price_state::util::eligible_for_stable_quote_conversion;

use crate::worker::PriceReporterConfig;

/// Get the set of tokens to stream prices for
///
/// For now this is just all the base tokens in the token mapping
pub(crate) fn get_tokens_to_stream() -> Vec<Token> {
    get_all_base_tokens()
}

/// Get all the (exchange, base, quote) tuples that are required to stream
/// prices for all the pairs in the token mapping
pub fn get_all_stream_tuples(config: &PriceReporterConfig) -> Vec<(Exchange, Token, Token)> {
    let usdc = Token::usdc();
    let all_pairs = get_tokens_to_stream();

    // Collect all the (exchange, base, quote) tuples that are required to
    // stream prices for all the pairs, some may duplicate for quote conversion
    // (USDT/USDC) so we use a set to deduplicate
    let mut all_stream_tuples = HashSet::new();
    for base in all_pairs {
        let streams = required_streams_for_pair(&base, &usdc, config);
        for (exchange, base, quote) in streams {
            all_stream_tuples.insert((exchange, base, quote));
        }
    }

    all_stream_tuples.into_iter().collect_vec()
}

/// Returns the set of exchanges that support both tokens in the pair.
///
/// Note: This does not mean that each exchange has a market for the pair,
/// just that it separately lists both tokens.
pub fn get_supported_exchanges(
    base_token: &Token,
    quote_token: &Token,
    config: &PriceReporterConfig,
) -> Vec<Exchange> {
    // Get the exchanges that list both tokens, and filter out the ones that
    // are not configured
    let listing_exchanges = get_listing_exchanges(base_token, quote_token);
    listing_exchanges
        .into_iter()
        .filter(|exchange| config.exchange_configured(*exchange))
        .collect_vec()
}

/// Returns the list of exchanges that list both the base and quote tokens.
///
/// Note: This does not mean that each exchange has a market for the pair,
/// just that it separately lists both tokens.
pub fn get_listing_exchanges(base_token: &Token, quote_token: &Token) -> Vec<Exchange> {
    // Compute the intersection of the supported exchanges for each of the assets
    // in the pair
    let base_token_supported_exchanges = base_token.supported_exchanges();
    let quote_token_supported_exchanges = quote_token.supported_exchanges();
    base_token_supported_exchanges
        .intersection(&quote_token_supported_exchanges)
        .copied()
        .collect_vec()
}

/// Returns the (exchange, base, quote) tuples for which price streams are
/// required to accurately compute the price for the (requested_base,
/// requested_quote) pair
pub fn required_streams_for_pair(
    requested_base: &Token,
    requested_quote: &Token,
    config: &PriceReporterConfig,
) -> Vec<(Exchange, Token, Token)> {
    let mut streams = Vec::new();
    let exchanges = get_supported_exchanges(requested_base, requested_quote, config);

    for exchange in exchanges {
        let pairs =
            if eligible_for_stable_quote_conversion(requested_base, requested_quote, &exchange) {
                let default_stable = default_exchange_stable(&exchange);
                vec![
                    (exchange, requested_base.clone(), default_stable.clone()),
                    (exchange, requested_quote.clone(), default_stable),
                ]
            } else {
                vec![(exchange, requested_base.clone(), requested_quote.clone())]
            };

        streams.extend(pairs);
    }

    streams
}
