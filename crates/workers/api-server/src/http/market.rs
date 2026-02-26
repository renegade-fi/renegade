//! Route handlers for market operations

use async_trait::async_trait;
use circuit_types::fixed_point::FixedPoint;
use external_api::{
    EmptyRequestResponse,
    http::market::{GetMarketDepthByMintResponse, GetMarketDepthsResponse, GetMarketsResponse},
    types::{
        ApiToken, DepthSide, MarketDepth, MarketInfo,
        external_match::{ApiTimestampedPrice, FeeTakeRate},
    },
};
use futures::future::join_all;
use hyper::HeaderMap;
use price_state::PriceStreamStates;
use state::State;
use types_account::pair::Pair;
use types_core::{Token, get_all_base_tokens};
use util::on_chain::get_protocol_fee;

use crate::{
    error::ApiServerError,
    param_parsing::parse_token_from_params,
    router::{QueryParams, TypedHandler, UrlParams},
};

// --------------------------
// | MarketDataCalculator   |
// --------------------------

/// Helper for computing market info and depth
#[derive(Clone)]
pub(super) struct MarketDataCalculator {
    /// The relayer state
    state: State,
    /// The price stream states
    price_streams: PriceStreamStates,
}

impl MarketDataCalculator {
    /// Constructor
    pub fn new(state: State, price_streams: PriceStreamStates) -> Self {
        Self { state, price_streams }
    }

    /// Get fee rates for a token
    fn get_fee_rates(&self, token: &Token) -> Result<FeeTakeRate, ApiServerError> {
        let ticker = token.get_ticker().unwrap_or_default();
        let relayer_fee: FixedPoint = self.state.get_relayer_fee(&ticker)?;
        let protocol_fee: FixedPoint =
            get_protocol_fee(&token.get_alloy_address(), &Token::usdc().get_alloy_address());

        Ok(FeeTakeRate { relayer_fee_rate: relayer_fee, protocol_fee_rate: protocol_fee })
    }

    /// Get market info for a token
    fn get_market_info(&self, token: &Token) -> Result<MarketInfo, ApiServerError> {
        let base = ApiToken::from(token.clone());
        let quote = ApiToken::from(Token::usdc());
        let price: ApiTimestampedPrice = self.price_streams.peek_timestamped_price(token)?.into();
        let fees = self.get_fee_rates(token)?;

        Ok(MarketInfo {
            base,
            quote,
            price,
            internal_match_fee_rates: fees.clone(),
            // At the moment, the relayer does not differentiate between internal and external match
            // fee rates
            external_match_fee_rates: fees,
        })
    }

    /// Get market depth for a token
    async fn get_market_depth(&self, token: &Token) -> Result<MarketDepth, ApiServerError> {
        let market = self.get_market_info(token)?;
        let pair = Pair::new(token.get_alloy_address(), Token::usdc().get_alloy_address());

        let (buy_amount_quote, sell_amount_base) = self.state.get_liquidity_for_pair(&pair).await;

        // Sell side: we have base token amounts
        let sell_usd = token.convert_to_decimal(sell_amount_base) * market.price.price;
        let sell = DepthSide { total_quantity: sell_amount_base, total_quantity_usd: sell_usd };

        // Buy side: we have quote (USDC) amounts, convert to base token units
        let buy_usd = Token::usdc().convert_to_decimal(buy_amount_quote);
        let buy_quantity_base = if market.price.price > 0.0 {
            let base_decimal = buy_usd / market.price.price;
            token.convert_from_decimal(base_decimal)
        } else {
            0u128
        };
        let buy = DepthSide { total_quantity: buy_quantity_base, total_quantity_usd: buy_usd };

        Ok(MarketDepth { market, buy, sell })
    }
}

// --------------------
// | Market Handlers  |
// --------------------

/// Handler for GET /v2/markets
pub struct GetMarketsHandler {
    /// The market data calculator
    calculator: MarketDataCalculator,
}

impl GetMarketsHandler {
    /// Constructor
    pub fn new(calculator: MarketDataCalculator) -> Self {
        Self { calculator }
    }
}

#[async_trait]
impl TypedHandler for GetMarketsHandler {
    type Request = EmptyRequestResponse;
    type Response = GetMarketsResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let tokens = get_all_base_tokens();
        let markets =
            tokens.iter().filter_map(|t| self.calculator.get_market_info(t).ok()).collect();
        Ok(GetMarketsResponse { markets })
    }
}

/// Handler for GET /v2/markets/depth
pub struct GetMarketDepthsHandler {
    /// The market data calculator
    calculator: MarketDataCalculator,
}

impl GetMarketDepthsHandler {
    /// Constructor
    pub fn new(calculator: MarketDataCalculator) -> Self {
        Self { calculator }
    }
}

#[async_trait]
impl TypedHandler for GetMarketDepthsHandler {
    type Request = EmptyRequestResponse;
    type Response = GetMarketDepthsResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        _params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let tokens = get_all_base_tokens();
        let futs = tokens
            .iter()
            .map(|t| async { self.calculator.get_market_depth(t).await })
            .collect::<Vec<_>>();
        let results = join_all(futs).await;
        let market_depths = results.into_iter().filter_map(|r| r.ok()).collect();
        Ok(GetMarketDepthsResponse { market_depths })
    }
}

/// Handler for GET /v2/markets/:mint/depth
pub struct GetMarketDepthByMintHandler {
    /// The market data calculator
    calculator: MarketDataCalculator,
}

impl GetMarketDepthByMintHandler {
    /// Constructor
    pub fn new(calculator: MarketDataCalculator) -> Self {
        Self { calculator }
    }
}

#[async_trait]
impl TypedHandler for GetMarketDepthByMintHandler {
    type Request = EmptyRequestResponse;
    type Response = GetMarketDepthByMintResponse;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let token = parse_token_from_params(&params)?;
        let market_depth = self.calculator.get_market_depth(&token).await?;
        Ok(GetMarketDepthByMintResponse { market_depth })
    }
}

/// Handler for GET /v2/markets/:mint/price
pub struct GetMarketPriceHandler {
    /// The price stream states
    price_streams: PriceStreamStates,
}

impl GetMarketPriceHandler {
    /// Constructor
    pub fn new(price_streams: PriceStreamStates) -> Self {
        Self { price_streams }
    }
}

#[async_trait]
impl TypedHandler for GetMarketPriceHandler {
    type Request = EmptyRequestResponse;
    type Response = ApiTimestampedPrice;

    async fn handle_typed(
        &self,
        _headers: HeaderMap,
        _req: Self::Request,
        params: UrlParams,
        _query_params: QueryParams,
    ) -> Result<Self::Response, ApiServerError> {
        let token = parse_token_from_params(&params)?;
        let price: ApiTimestampedPrice = self.price_streams.peek_timestamped_price(&token)?.into();
        Ok(price)
    }
}
