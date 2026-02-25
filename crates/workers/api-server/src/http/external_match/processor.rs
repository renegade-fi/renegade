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
        ApiExternalAssetTransfer, ApiExternalMatchResult, ApiExternalQuote, ApiSignedQuote,
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
use types_core::{HmacKey, TimestampedPrice, TimestampedPriceFp};
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
        let price_fp = self.get_price(&pair)?;

        // Determine fee rates before normalizing output-denominated exact orders
        let fee_override = req.options.relayer_fee_rate.map(FixedPoint::from_f64_round_down);
        let fee_rates = self.get_fee_rates_for_pair(&pair, fee_override)?;

        // Build the matching engine job
        let (order, grossed_output) = Self::normalize_external_order_for_matching(
            req.external_order.clone(),
            price_fp,
            &fee_rates,
        )?;
        let options = Self::quote_engine_options(price_fp, fee_rates.relayer_fee_rate);

        let (job, topic) = MatchingEngineWorkerJob::new_external_match_job(order.clone(), options);

        // Send the job to the matching engine
        let match_res = self.forward_quote_request(job, topic).await?;

        // Build an API response
        // For exact-output orders, recompute amount_in using the on-chain price
        // to avoid precision loss from FixedPoint::inverse() in the
        // quoted_price -> on_chain_price roundtrip.
        let amount_in =
            Self::compute_external_amount_in(order.amount_in(), grossed_output, &match_res.price);
        let obligation = match_res.to_external_obligation(amount_in);
        let fee_take = fee_rates.compute_fee_take(obligation.amount_out);

        // Compute the send and receive amounts
        // Again, we use the requested amount to size the match
        let net_out = obligation.amount_out - fee_take.total();
        let send = ApiExternalAssetTransfer::new(obligation.input_token, obligation.amount_in);
        let receive = ApiExternalAssetTransfer::new(obligation.output_token, net_out);

        let price = TimestampedPrice::from(price_fp);
        Ok(ApiExternalQuote {
            order: req.external_order,
            match_result: ApiExternalMatchResult {
                input_mint: obligation.input_token,
                output_mint: obligation.output_token,
                input_amount: obligation.amount_in,
                output_amount: obligation.amount_out,
                price_fp: price_fp.into(),
            },
            fees: fee_take.into(),
            send,
            receive,
            price: price.into(),
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

        // Resolve price once, then use it consistently across
        // normalization and matching-engine options.
        let external_order = req.order.get_external_order();
        let pair = Pair::new(external_order.input_mint, external_order.output_mint);
        let price = self.assembly_price(&req, &pair)?;
        let fee_override = req.options.relayer_fee_rate.map(FixedPoint::from_f64_round_down);
        let fee_rates = self.get_fee_rates_for_pair(&pair, fee_override)?;

        // Build the matching engine job
        let (order, grossed_output) =
            Self::normalize_external_order_for_matching(external_order.clone(), price, &fee_rates)?;
        let options = Self::assembly_engine_options(
            &external_order,
            req.options.matching_pool.clone(),
            price,
            fee_rates.relayer_fee_rate,
        );
        let (job, topic) = MatchingEngineWorkerJob::new_external_match_job(order.clone(), options);

        // Send the job to the matching engine
        let (match_res, settlement_bundle) = self.forward_assemble_request(job, topic).await?;

        // For exact-output orders, recompute amount_in using the on-chain price
        // to avoid precision loss from FixedPoint::inverse() in the
        // quoted_price -> on_chain_price roundtrip.
        let amount_in =
            Self::compute_external_amount_in(order.amount_in(), grossed_output, &match_res.price);

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
            amount_in,
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
        order: &ExternalOrder,
        matching_pool: Option<types_account::MatchingPoolName>,
        price: TimestampedPriceFp,
        effective_relayer_fee_rate: FixedPoint,
    ) -> ExternalMatchingEngineOptions {
        ExternalMatchingEngineOptions::default()
            .with_matching_pool(matching_pool)
            .with_min_input_amount(order.min_fill_size)
            .with_relayer_fee_rate(effective_relayer_fee_rate)
            .with_price(price)
    }

    /// Build matching-engine options for a quote request with an explicit
    /// effective relayer fee rate.
    fn quote_engine_options(
        price: TimestampedPriceFp,
        effective_relayer_fee_rate: FixedPoint,
    ) -> ExternalMatchingEngineOptions {
        ExternalMatchingEngineOptions::default()
            .with_only_quote(true)
            .with_price(price)
            .with_relayer_fee_rate(effective_relayer_fee_rate)
    }

    /// Resolve the assembly execution price once.
    ///
    /// Use the quoted price when available and lazily fall back to a fresh
    /// price otherwise.
    fn assembly_price(
        &self,
        req: &AssembleExternalMatchRequest,
        pair: &Pair,
    ) -> Result<TimestampedPriceFp, ApiServerError> {
        match &req.order {
            ExternalMatchAssemblyType::QuotedOrder { signed_quote, .. } => {
                Ok(signed_quote.quote.match_result.price_fp.clone().into())
            },
            ExternalMatchAssemblyType::DirectOrder { .. } => self.get_price(pair),
        }
    }

    /// Normalize an external order into the form expected by the matching
    /// engine
    ///
    /// This applies v1-compatible exact-output fee gross-up semantics and then
    /// converts any output-sized order to an input-sized order at the given
    /// price.
    ///
    /// Returns the Order and, for exact-output orders, the grossed-up output
    /// amount (needed to recompute `external_party_amount_in` against the
    /// on-chain price after matching).
    fn normalize_external_order_for_matching(
        external_order: ExternalOrder,
        execution_price: TimestampedPriceFp,
        fee_rates: &FeeRates,
    ) -> Result<(Order, Option<u128>), ApiServerError> {
        let external_order = Self::normalize_exact_amount_order(external_order, fee_rates)?;
        let grossed_output =
            if external_order.use_exact_output_amount && external_order.output_amount > 0 {
                Some(external_order.output_amount)
            } else {
                None
            };
        Ok((external_order.into_order_with_price(execution_price.price), grossed_output))
    }

    /// Normalize exact-amount semantics before converting to matching-engine
    /// order sizing.
    ///
    /// For exact output orders where `output_amount` is set, we gross up the
    /// output to pre-fee units so that after fees the user receives the
    /// requested net amount. Input-sized exact orders are left unchanged.
    ///
    /// Fees are taken from the external party's output side only (see
    /// `ExternalSettlementLib.allocateExternalPartyTransfers` in the
    /// contracts). We divide by `(1 - f)` so that after the on-chain fee
    /// deduction the net received amount meets or exceeds the request.
    fn normalize_exact_amount_order(
        mut external_order: ExternalOrder,
        fee_rates: &FeeRates,
    ) -> Result<ExternalOrder, ApiServerError> {
        if !external_order.use_exact_output_amount {
            return Ok(external_order);
        }
        if external_order.output_amount == 0 {
            return Ok(external_order);
        }

        let total_fee = fee_rates.relayer_fee_rate + fee_rates.protocol_fee_rate;
        let one_minus_fee = FixedPoint::one() - total_fee;
        if one_minus_fee <= FixedPoint::zero() {
            return Err(internal_error("invalid external match fee configuration"));
        }

        // floor(N / (1-f)) gives a value G such that G*(1-f) > N-1, which
        // guarantees net >= N after integer fee deduction.  The ceiling in
        // into_order_with_price (ceil_div_int) absorbs the price-roundtrip
        // rounding separately.
        external_order.output_amount =
            scalar_to_u128(&one_minus_fee.floor_div_int(external_order.output_amount));
        Ok(external_order)
    }

    /// Compute `external_party_amount_in` for the settlement transaction.
    ///
    /// For exact-output orders we recompute the input amount using the
    /// on-chain price from the `BoundedMatchResult` rather than the server's
    /// price.  The matching engine inverts the server price via
    /// `FixedPoint::inverse()`, which introduces rounding error.  Using the
    /// on-chain price directly ensures the contract's
    /// `divIntegerByFixedPoint(amount_in, price)` reproduces the grossed-up
    /// output exactly.
    fn compute_external_amount_in(
        default_amount_in: u128,
        grossed_output: Option<u128>,
        on_chain_price: &FixedPoint,
    ) -> u128 {
        match grossed_output {
            Some(grossed) => {
                // on_chain_price is out_token/in_token from the internal
                // party's perspective, which equals in_token/out_token for the
                // external
                // party.  We need:
                //   floor(amount_in / on_chain_price) >= grossed
                // i.e. amount_in >= grossed * on_chain_price
                // Use floor_mul + 1 as a ceiling to guarantee the inequality.
                scalar_to_u128(&on_chain_price.floor_mul_int(grossed)) + 1
            },
            None => default_amount_in,
        }
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
    fn get_price(&self, pair: &Pair) -> Result<TimestampedPriceFp, ApiServerError> {
        self.price_streams
            .get_output_quoted_price(pair)
            .map(TimestampedPriceFp::from)
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

    /// Get the fee rates for a match pair
    fn get_fee_rates_for_pair(
        &self,
        pair: &Pair,
        relayer_fee_override: Option<FixedPoint>,
    ) -> Result<FeeRates, ApiServerError> {
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

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;
    use external_api::types::ExternalOrder;

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    /// Build a dummy address from a single byte
    fn dummy_addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    /// Build a default external order for testing
    fn mock_external_order() -> ExternalOrder {
        ExternalOrder {
            input_mint: dummy_addr(0x01),
            output_mint: dummy_addr(0x02),
            input_amount: 100,
            output_amount: 0,
            use_exact_output_amount: false,
            min_fill_size: 25,
        }
    }

    /// Build fee rates from f64 values
    fn mock_fee_rates(relayer: f64, protocol: f64) -> FeeRates {
        FeeRates::new(
            FixedPoint::from_f64_round_down(relayer),
            FixedPoint::from_f64_round_down(protocol),
        )
    }

    /// Simulate the production gross-up → settlement pipeline and return
    /// the net output amount the user would receive.
    ///
    /// Models the real flow:
    ///   1. Gross up output_amount by floor(N/(1-f))
    ///   2. Matching engine inverts server price to get on-chain price
    ///   3. compute_external_amount_in recomputes amount_in from on-chain price
    ///   4. Contract computes amount_out = floor(amount_in / on_chain_price),
    ///      which is floor_div_int(on_chain_price, amount_in)
    ///   5. Contract deducts fee from amount_out -> net received
    fn simulate_net_output(
        requested: u128,
        fee_rates: &FeeRates,
        server_price: &TimestampedPriceFp,
    ) -> u128 {
        let order = ExternalOrder {
            input_amount: 0,
            output_amount: requested,
            use_exact_output_amount: true,
            ..mock_external_order()
        };

        // Step 1: gross up
        let grossed =
            ExternalMatchProcessor::normalize_exact_amount_order(order, fee_rates).unwrap();
        let grossed_output = grossed.output_amount;

        // Step 2: matching engine inverts server price
        let on_chain_price = server_price.price.inverse().expect("price is zero");

        // Step 3: recompute amount_in using on-chain price
        let amount_in = ExternalMatchProcessor::compute_external_amount_in(
            0, // default unused
            Some(grossed_output),
            &on_chain_price,
        );

        // Step 4: contract computes amount_out = floor(amount_in / on_chain_price)
        // This matches Solidity's divIntegerByFixedPoint
        let amount_out = scalar_to_u128(&on_chain_price.floor_div_int(amount_in));

        // Step 5: output-side fee deduction
        let fee = fee_rates.compute_fee_take(amount_out);
        amount_out - fee.total()
    }

    // ---------
    // | Tests |
    // ---------

    /// Build a `TimestampedPriceFp` from an f64 price
    fn mock_price(price: f64) -> TimestampedPriceFp {
        TimestampedPriceFp { price: FixedPoint::from_f64_round_down(price), timestamp: 123 }
    }

    /// Tests that an exact-receive order is grossed up to account for fees
    #[test]
    fn test_normalize_exact_receive_order_applies_fee_gross_up() {
        let order = ExternalOrder {
            input_amount: 0,
            output_amount: 970,
            use_exact_output_amount: true,
            ..mock_external_order()
        };
        let fee_rates = mock_fee_rates(0.02, 0.01);
        let price = mock_price(2.0);

        let (normalized, grossed) =
            ExternalMatchProcessor::normalize_external_order_for_matching(order, price, &fee_rates)
                .unwrap();

        // floor(970 / fp(0.97)) = 999 grossed output
        // (fp(0.97) is slightly > 0.97 due to f64 precision in from_f64_round_down)
        assert_eq!(grossed, Some(999));
        // at price 2.0 → ceil(999/2) = 500 input
        assert_eq!(normalized.amount_in(), 500);
    }

    /// Tests that an exact-spend order (input-anchored) passes through
    /// normalization without changing the input amount
    #[test]
    fn test_normalize_exact_spend_order_keeps_input_anchor() {
        let order = ExternalOrder {
            input_amount: 500,
            output_amount: 0,
            use_exact_output_amount: true,
            ..mock_external_order()
        };
        let fee_rates = mock_fee_rates(0.02, 0.01);
        let price = mock_price(2.0);

        let (normalized, grossed) =
            ExternalMatchProcessor::normalize_external_order_for_matching(order, price, &fee_rates)
                .unwrap();

        assert_eq!(grossed, None);
        assert_eq!(normalized.amount_in(), 500);
    }

    /// Tests that assembly options always carry the resolved effective relayer
    /// fee rate, regardless of request override presence.
    #[test]
    fn test_assembly_engine_options_uses_effective_relayer_fee_rate() {
        let order = mock_external_order();
        let effective_fee = FixedPoint::from_f64_round_down(0.0001);

        let options = ExternalMatchProcessor::assembly_engine_options(
            &order,
            None,
            mock_price(2.0),
            effective_fee,
        );

        assert_eq!(options.relayer_fee_rate, effective_fee);
        assert_eq!(options.min_input_amount, Some(order.min_fill_size));
    }

    /// Tests that assembly options use the provided assembly price.
    #[test]
    fn test_assembly_engine_options_uses_provided_price() {
        let order = mock_external_order();
        let price = mock_price(2.0);
        let effective_fee = FixedPoint::from_f64_round_down(0.0001);
        let options =
            ExternalMatchProcessor::assembly_engine_options(&order, None, price, effective_fee);

        assert_eq!(options.price.expect("price missing").price.to_f64(), 2.0);
    }

    /// Tests that quote options propagate the resolved effective relayer fee
    /// rate into the matching-engine job options.
    #[test]
    fn test_quote_engine_options_uses_effective_relayer_fee_rate() {
        let effective_fee = FixedPoint::from_f64_round_down(0.0002);

        let options = ExternalMatchProcessor::quote_engine_options(mock_price(1.5), effective_fee);

        assert!(options.only_quote);
        assert_eq!(options.relayer_fee_rate, FixedPoint::from_f64_round_down(0.0002));
        assert_eq!(options.price.expect("price missing").price.to_f64(), 1.5);
    }

    /// Tests the end-to-end invariant: after gross-up, price conversion,
    /// and fee deduction on both sides, the net output is at least the
    /// requested amount. This is the property customers depend on.
    #[test]
    fn test_gross_up_fee_deduction_preserves_requested_output() {
        let test_cases: &[(u128, f64, f64, f64)] = &[
            // (requested_output, relayer_fee, protocol_fee, price)
            (100, 0.02, 0.01, 2.0),
            (100, 0.02, 0.01, 0.5),
            (970, 0.02, 0.01, 2.0),
            (999, 0.005, 0.005, 0.1),
            (1_000_000, 0.02, 0.01, 1965.0), // realistic wETH/USDC
            (30_000_000, 0.0002, 0.0001, 0.0005), // 30 USDC, realistic fees
            (7919, 0.017, 0.013, 0.75),      // prime amount, asymmetric fees
            (10_000, 0.0, 0.0, 2.0),         // zero fees
            (500, 0.0, 0.01, 1.0),           // relayer-only zero
            (123_456_789, 0.02, 0.01, 10.0), // large amount
        ];

        for &(requested, relayer_rate, protocol_rate, price) in test_cases {
            let fee_rates = mock_fee_rates(relayer_rate, protocol_rate);
            let price = mock_price(price);
            let net = simulate_net_output(requested, &fee_rates, &price);

            assert!(
                net >= requested,
                "Expected net output {net} >= requested {requested} \
                 (relayer={relayer_rate}, protocol={protocol_rate})",
            );
        }
    }
}
