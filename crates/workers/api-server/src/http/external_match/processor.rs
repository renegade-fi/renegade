//! The external match processor

use std::time::Duration;

use circuit_types::fixed_point::FixedPoint;
use darkpool_types::{bounded_match_result::BoundedMatchResult, fee::FeeRates};
use external_api::{
    http::external_match::ExternalQuoteRequest,
    types::{ApiExternalAssetTransfer, ApiExternalQuote, ApiSignedQuote, ApiTimestampedPrice},
};
use job_types::matching_engine::{
    ExternalMatchingEngineOptions, MatchingEngineWorkerJob, MatchingEngineWorkerQueue,
};
use state::State;
use system_bus::{SystemBus, SystemBusMessage};
use types_account::order::Order;
use types_core::HmacKey;
use util::{get_current_time_millis, on_chain::get_external_match_fee};

use crate::error::{ApiServerError, internal_error, no_content};

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
    /// The system bus
    bus: SystemBus,
    /// The work queue for the matching engine
    matching_engine_worker_queue: MatchingEngineWorkerQueue,
    /// The relayer state
    state: State,
}

impl ExternalMatchProcessor {
    /// Constructor
    pub fn new(
        admin_key: HmacKey,
        bus: SystemBus,
        matching_engine_worker_queue: MatchingEngineWorkerQueue,
        state: State,
    ) -> Self {
        Self { admin_key, bus, matching_engine_worker_queue, state }
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
        // Build the matching engine job
        let options = ExternalMatchingEngineOptions::default().with_only_quote(true);
        let order = Order::from(req.external_order.clone());
        let (job, topic) = MatchingEngineWorkerJob::new_external_match_job(order.clone(), options);

        // Send the job to the matching engine
        let match_res = self.forward_quote_request(job, topic).await?;
        let price = match_res.price;

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

    // --- Helpers --- //

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
        let base = order.pair().base_token();
        let protocol_fee = get_external_match_fee(&base.get_alloy_address());
        let relayer_fee = match relayer_fee_override {
            Some(fee) => fee,
            None => {
                let ticker = base.get_ticker().expect("base token has no ticker");
                self.state.get_relayer_fee(&ticker)?
            },
        };

        Ok(FeeRates::new(relayer_fee, protocol_fee))
    }
}
