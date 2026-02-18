//! The external match processor

use std::time::Duration;

use alloy::{
    network::TransactionBuilder, primitives::U256, rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use circuit_types::fixed_point::FixedPoint;
use crypto::fields::scalar_to_u128;
use darkpool_client::DarkpoolClient;
use darkpool_types::{bounded_match_result::BoundedMatchResult, fee::FeeRates};
use external_api::{
    http::external_match::{
        AssembleExternalMatchRequest, ExternalMatchAssemblyType, ExternalQuoteRequest,
    },
    types::{
        ApiExternalAssetTransfer, ApiExternalQuote, ApiSignedQuote, ApiTimestampedPrice,
        BoundedExternalMatchApiBundle, ExternalOrder,
    },
};
use job_types::matching_engine::{
    ExternalMatchingEngineOptions, MatchingEngineWorkerJob, MatchingEngineWorkerQueue,
};
use price_state::PriceStreamStates;
use renegade_solidity_abi::v2::IDarkpoolV2::{self, SettlementBundle};
use state::State;
use system_bus::{SystemBus, SystemBusMessage};
use types_account::{order::Order, pair::Pair};
use types_core::{HmacKey, TimestampedPrice};
use util::{get_current_time_millis, on_chain::get_protocol_fee};

use crate::error::{ApiServerError, internal_error, no_content, unauthorized};

// -------------
// | Constants |
// -------------

/// The timeout to use when waiting for a response from the matching engine
const MATCHING_ENGINE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// The deadline for a quote in milliseconds
const QUOTE_DEADLINE: Duration = Duration::from_secs(10);

/// Error message for no external match found
const ERR_NO_EXTERNAL_MATCH_FOUND: &str = "no external match found";

// -------------
// | Processor |
// -------------

/// The external match processor
#[derive(Clone)]
pub struct ExternalMatchProcessor {
    /// The admin API key, used to sign quotes
    admin_key: HmacKey,
    /// The darkpool client
    darkpool_client: DarkpoolClient,
    /// The system bus
    bus: SystemBus,
    /// The work queue for the matching engine
    matching_engine_worker_queue: MatchingEngineWorkerQueue,
    /// The price streams from the price reporter
    price_streams: PriceStreamStates,
    /// The relayer state
    state: State,
}

impl ExternalMatchProcessor {
    /// Constructor
    pub fn new(
        admin_key: HmacKey,
        darkpool_client: DarkpoolClient,
        bus: SystemBus,
        matching_engine_worker_queue: MatchingEngineWorkerQueue,
        price_streams: PriceStreamStates,
        state: State,
    ) -> Self {
        Self { admin_key, darkpool_client, bus, matching_engine_worker_queue, price_streams, state }
    }

    // --- Quote --- //

    /// Fetch a signed quote for an external order
    pub(crate) async fn fetch_signed_quote(
        &self,
        req: ExternalQuoteRequest,
    ) -> Result<ApiSignedQuote, ApiServerError> {
        let quote = self.fetch_quote(req).await?;
        let deadline = quote.timestamp + QUOTE_DEADLINE.as_millis() as u64;

        // Sign the quote
        let quote_bytes = serde_json::to_vec(&quote).map_err(internal_error)?;
        let signature = self.admin_key.compute_mac(&quote_bytes);
        Ok(ApiSignedQuote { quote, signature, deadline })
    }

    /// Fetch a quote for an external order
    async fn fetch_quote(
        &self,
        req: ExternalQuoteRequest,
    ) -> Result<ApiExternalQuote, ApiServerError> {
        // Fetch the price for the pair; this effectively adds to the delay
        // between price sampling and settlement, but is acceptable for simplicity
        let pair = Pair::new(req.external_order.input_mint, req.external_order.output_mint);
        let price = self.get_price(&pair)?;

        // Build the matching engine job
        let order = req.external_order.clone().into_order_with_price(price.price);
        let options =
            ExternalMatchingEngineOptions::default().with_only_quote(true).with_price(price);

        let (job, topic) = MatchingEngineWorkerJob::new_external_match_job(order.clone(), options);

        // Send the job to the matching engine
        let match_res = self.forward_quote_request(job, topic).await?;

        // The bounded match result returned by the matching engine is constructed from
        // the internal party's perspective. Thus we must invert the price to
        // have it in terms of the external party's output/input price.
        let price = match_res.price.inverse().expect("match price is zero");

        // Build an API response
        let fee_override = req.options.relayer_fee_rate.map(FixedPoint::from_f64_round_down);
        let fees = self.get_fee_rates(&order, fee_override).await?;

        // Compute the fee take
        // We use the requested amount to compute the fee take rather than one of the
        // bounds
        let obligation = match_res.to_external_obligation(order.amount_in());
        let fee_take = fees.compute_fee_take(obligation.amount_out);

        // Compute the send and receive amounts
        // Again, we use the requested amount to size the match
        let net_out = obligation.amount_out - fee_take.total();
        let send = ApiExternalAssetTransfer::new(obligation.input_token, obligation.amount_in);
        let receive = ApiExternalAssetTransfer::new(obligation.output_token, net_out);

        Ok(ApiExternalQuote {
            order: req.external_order,
            match_result: obligation.into(),
            fees: fee_take.into(),
            send,
            receive,
            price: ApiTimestampedPrice::new(price),
            timestamp: get_current_time_millis(),
        })
    }

    /// Forward a quote request to the matching engine and expect back a match
    /// result
    async fn forward_quote_request(
        &self,
        job: MatchingEngineWorkerJob,
        topic: String,
    ) -> Result<BoundedMatchResult, ApiServerError> {
        let msg = self.forward_job_wait_for_response(job, topic).await?;
        match msg {
            SystemBusMessage::ExternalOrderQuote { quote } => Ok(quote),
            SystemBusMessage::NoExternalMatchFound => Err(no_content(ERR_NO_EXTERNAL_MATCH_FOUND)),
            _ => Err(internal_error("unexpected system bus message")),
        }
    }

    // --- Assemble --- //

    /// Assemble a match bundle
    pub async fn assemble_match_bundle(
        &self,
        req: AssembleExternalMatchRequest,
    ) -> Result<BoundedExternalMatchApiBundle, ApiServerError> {
        // First, verify the quote signature if a quote is provided
        self.verify_quote_signature(&req)?;

        // Fetch the price for the pair; this effectively adds to the delay
        // between price sampling and settlement, but is acceptable for simplicity
        let external_order = req.order.get_external_order();
        let pair = Pair::new(external_order.input_mint, external_order.output_mint);
        let price = self.get_price(&pair)?;

        // Build the matching engine job
        let order = external_order.clone().into_order_with_price(price.price);
        let options = self.assembly_engine_options(&external_order, &req, price);
        let (job, topic) = MatchingEngineWorkerJob::new_external_match_job(order.clone(), options);

        // Send the job to the matching engine
        let (match_res, settlement_bundle) = self.forward_assemble_request(job, topic).await?;
        let fee_override = req.options.relayer_fee_rate.map(FixedPoint::from_f64_round_down);
        let fee_rates = self.get_fee_rates(&order, fee_override).await?;

        // Compute the send bounds
        let send_mint = match_res.internal_party_output_token;
        let min_send_amt = match_res.price.floor_mul_int(match_res.min_internal_party_amount_in);
        let max_send_amt = match_res.price.floor_mul_int(match_res.max_internal_party_amount_in);
        let min_send = ApiExternalAssetTransfer::new(send_mint, scalar_to_u128(&min_send_amt));
        let max_send = ApiExternalAssetTransfer::new(send_mint, scalar_to_u128(&max_send_amt));

        // Compute the receive bounds
        let receive_mint = match_res.internal_party_input_token;
        let min_receive_amt = match_res.min_internal_party_amount_in;
        let max_receive_amt = match_res.max_internal_party_amount_in;
        let min_fee = fee_rates.compute_fee_take(min_receive_amt);
        let max_fee = fee_rates.compute_fee_take(max_receive_amt);
        let min_net = min_receive_amt - min_fee.total();
        let max_net = max_receive_amt - max_fee.total();
        let min_receive = ApiExternalAssetTransfer::new(receive_mint, min_net);
        let max_receive = ApiExternalAssetTransfer::new(receive_mint, max_net);

        // Build the settlement transaction
        let settlement_tx = self.build_settlement_transaction(
            match_res.clone(),
            settlement_bundle,
            &req,
            order.amount_in(),
        );

        // Build an API response
        let bundle = BoundedExternalMatchApiBundle {
            match_result: match_res.clone().into(),
            fee_rates: fee_rates.into(),
            max_receive,
            min_receive,
            max_send,
            min_send,
            settlement_tx,
            deadline: match_res.block_deadline,
        };

        Ok(bundle)
    }

    /// Verify the quote signature on an assembly request if a quote is provided
    fn verify_quote_signature(
        &self,
        req: &AssembleExternalMatchRequest,
    ) -> Result<(), ApiServerError> {
        if let ExternalMatchAssemblyType::QuotedOrder { signed_quote, .. } = &req.order {
            let quote_bytes = serde_json::to_vec(&signed_quote.quote).map_err(internal_error)?;
            let sig = signed_quote.signature.clone();
            let verified = self.admin_key.verify_mac(&quote_bytes, &sig);
            if !verified {
                return Err(unauthorized("invalid quote signature"));
            }
        };

        Ok(())
    }

    /// Build the matching engine options for an assembly request
    fn assembly_engine_options(
        &self,
        order: &ExternalOrder,
        req: &AssembleExternalMatchRequest,
        price: TimestampedPrice,
    ) -> ExternalMatchingEngineOptions {
        let mut options = ExternalMatchingEngineOptions::default()
            .with_matching_pool(req.options.matching_pool.clone())
            .with_min_input_amount(order.min_fill_size);

        // Add a fee rate
        if let Some(relayer_fee_rate) = req.options.relayer_fee_rate {
            let fee_rate = FixedPoint::from_f64_round_down(relayer_fee_rate);
            options = options.with_relayer_fee_rate(fee_rate);
        }

        // If this order comes from a previously generated quote, use the quoted
        // price; otherwise use the price fetched at the processor level
        if let ExternalMatchAssemblyType::QuotedOrder { signed_quote, .. } = &req.order {
            let ts_price = signed_quote.quote.price.clone().into();
            options = options.with_price(ts_price);
        } else {
            options = options.with_price(price);
        }

        options
    }

    /// Forward an assembly request to the matching engine and expect back a
    /// match result
    async fn forward_assemble_request(
        &self,
        job: MatchingEngineWorkerJob,
        topic: String,
    ) -> Result<(BoundedMatchResult, SettlementBundle), ApiServerError> {
        let msg = self.forward_job_wait_for_response(job, topic).await?;
        match msg {
            SystemBusMessage::ExternalOrderBundle { match_result, settlement_bundle } => {
                Ok((match_result, settlement_bundle))
            },
            SystemBusMessage::NoExternalMatchFound => Err(no_content(ERR_NO_EXTERNAL_MATCH_FOUND)),
            _ => Err(internal_error("unexpected system bus message")),
        }
    }

    // --- Helpers --- //

    /// Get the output-quoted execution price for a pair
    fn get_price(&self, pair: &Pair) -> Result<TimestampedPrice, ApiServerError> {
        self.price_streams
            .get_output_quoted_price(pair)
            .map_err(|e| internal_error(format!("failed to fetch price: {e}")))
    }

    /// Forward a job to the matching engine and expect back a bus message
    async fn forward_job_wait_for_response(
        &self,
        job: MatchingEngineWorkerJob,
        topic: String,
    ) -> Result<SystemBusMessage, ApiServerError> {
        self.matching_engine_worker_queue.send(job).map_err(internal_error)?;
        let msg = self
            .bus
            .next_message_with_timeout(topic, MATCHING_ENGINE_RESPONSE_TIMEOUT)
            .await
            .map_err(internal_error)?;

        Ok(msg)
    }

    /// Get the fee rates for a match
    async fn get_fee_rates(
        &self,
        order: &Order,
        relayer_fee_override: Option<FixedPoint>,
    ) -> Result<FeeRates, ApiServerError> {
        let pair = order.pair();
        let (base, quote) = (pair.base_token(), pair.quote_token());
        let protocol_fee = get_protocol_fee(&base.get_alloy_address(), &quote.get_alloy_address());
        let relayer_fee = match relayer_fee_override {
            Some(fee) => fee,
            None => {
                let ticker = base.get_ticker().expect("base token has no ticker");
                self.state.get_relayer_fee(&ticker)?
            },
        };

        Ok(FeeRates::new(relayer_fee, protocol_fee))
    }

    /// Build a settlement transaction from a settlement bundle
    fn build_settlement_transaction(
        &self,
        match_res: BoundedMatchResult,
        settlement_bundle: SettlementBundle,
        req: &AssembleExternalMatchRequest,
        amount_in: u128,
    ) -> TransactionRequest {
        let call = IDarkpoolV2::settleExternalMatchCall {
            externalPartyAmountIn: U256::from(amount_in),
            recipient: req.receiver_address.unwrap_or_default(),
            matchResult: match_res.into(),
            internalPartySettlementBundle: settlement_bundle,
        };

        // Encode the call data and build a transaction request
        let calldata = call.abi_encode();
        let darkpool_address = self.darkpool_client.darkpool_addr();
        TransactionRequest::default().with_to(darkpool_address).with_input(calldata)
    }
}
