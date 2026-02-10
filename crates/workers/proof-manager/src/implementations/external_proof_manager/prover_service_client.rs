//! Implements the client for the prover service

use ark_mpc::network::PartyId;
use circuit_types::ProofLinkingHint;
use circuits_core::zk_circuits::{
    fees::{
        valid_note_redemption::{SizedValidNoteRedemptionWitness, ValidNoteRedemptionStatement},
        valid_private_protocol_fee_payment::{
            SizedValidPrivateProtocolFeePaymentWitness, ValidPrivateProtocolFeePaymentStatement,
        },
        valid_private_relayer_fee_payment::{
            SizedValidPrivateRelayerFeePaymentWitness, ValidPrivateRelayerFeePaymentStatement,
        },
        valid_public_protocol_fee_payment::{
            SizedValidPublicProtocolFeePaymentWitness, ValidPublicProtocolFeePaymentStatement,
        },
        valid_public_relayer_fee_payment::{
            SizedValidPublicRelayerFeePaymentWitness, ValidPublicRelayerFeePaymentStatement,
        },
    },
    settlement::{
        intent_and_balance_bounded_settlement::{
            IntentAndBalanceBoundedSettlementStatement, IntentAndBalanceBoundedSettlementWitness,
        },
        intent_and_balance_private_settlement::{
            IntentAndBalancePrivateSettlementStatement, IntentAndBalancePrivateSettlementWitness,
        },
        intent_and_balance_public_settlement::{
            IntentAndBalancePublicSettlementStatement, IntentAndBalancePublicSettlementWitness,
        },
        intent_only_bounded_settlement::{
            IntentOnlyBoundedSettlementStatement, IntentOnlyBoundedSettlementWitness,
        },
        intent_only_public_settlement::{
            IntentOnlyPublicSettlementStatement, IntentOnlyPublicSettlementWitness,
        },
    },
    valid_balance_create::{ValidBalanceCreateStatement, ValidBalanceCreateWitness},
    valid_deposit::{SizedValidDepositWitness, ValidDepositStatement},
    valid_order_cancellation::{
        SizedValidOrderCancellationWitness, ValidOrderCancellationStatement,
    },
    valid_withdrawal::{SizedValidWithdrawalWitness, ValidWithdrawalStatement},
    validity_proofs::{
        intent_and_balance::{
            IntentAndBalanceValidityStatement, SizedIntentAndBalanceValidityWitness,
        },
        intent_and_balance_first_fill::{
            IntentAndBalanceFirstFillValidityStatement,
            SizedIntentAndBalanceFirstFillValidityWitness,
        },
        intent_only::{IntentOnlyValidityStatement, SizedIntentOnlyValidityWitness},
        intent_only_first_fill::{
            IntentOnlyFirstFillValidityStatement, IntentOnlyFirstFillValidityWitness,
        },
        new_output_balance::{
            NewOutputBalanceValidityStatement, SizedNewOutputBalanceValidityWitness,
        },
        output_balance::{OutputBalanceValidityStatement, SizedOutputBalanceValidityWitness},
    },
};
use http_auth_basic::Credentials;
use job_types::proof_manager::ProofManagerResponse;
use reqwest::{
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use util::telemetry::propagation::add_trace_context_to_headers;

use crate::{
    error::ProofManagerError,
    implementations::external_proof_manager::api_types::{
        IntentAndBalanceBoundedSettlementRequest, IntentAndBalanceFirstFillValidityRequest,
        IntentAndBalancePrivateSettlementRequest, IntentAndBalancePublicSettlementRequest,
        IntentAndBalanceValidityRequest, IntentOnlyBoundedSettlementRequest,
        IntentOnlyFirstFillValidityRequest, IntentOnlyPublicSettlementRequest,
        IntentOnlyValidityRequest, NewOutputBalanceValidityRequest, OutputBalanceValidityRequest,
        PrivateSettlementProofResponse, ProofAndHintResponse, ProofResponse,
        SettlementProofResponse, ValidBalanceCreateRequest, ValidDepositRequest,
        ValidNoteRedemptionRequest, ValidOrderCancellationRequest,
        ValidPrivateProtocolFeePaymentRequest, ValidPrivateRelayerFeePaymentRequest,
        ValidPublicProtocolFeePaymentRequest, ValidPublicRelayerFeePaymentRequest,
        ValidWithdrawalRequest,
    },
    worker::ProofManagerConfig,
};
use types_proofs::{
    PrivateSettlementProofBundle, ProofAndHintBundle, ProofBundle, SettlementProofBundle,
};

/// The HTTP basic auth user name to use
const HTTP_BASIC_AUTH_USER: &str = "admin";

// ---------
// | Paths |
// ---------

// Update proofs
/// The API path for requesting a `VALID BALANCE CREATE` proof
const VALID_BALANCE_CREATE_PATH: &str = "/prove-valid-balance-create";
/// The API path for requesting a `VALID DEPOSIT` proof
const VALID_DEPOSIT_PATH: &str = "/prove-valid-deposit";
/// The API path for requesting a `VALID ORDER CANCELLATION` proof
const VALID_ORDER_CANCELLATION_PATH: &str = "/prove-valid-order-cancellation";
/// The API path for requesting a `VALID WITHDRAWAL` proof
const VALID_WITHDRAWAL_PATH: &str = "/prove-valid-withdrawal";
// Validity proofs
/// The API path for requesting an `INTENT AND BALANCE VALIDITY` proof
const INTENT_AND_BALANCE_VALIDITY_PATH: &str = "/prove-intent-and-balance-validity";
/// The API path for requesting an `INTENT AND BALANCE FIRST FILL VALIDITY`
/// proof
const INTENT_AND_BALANCE_FIRST_FILL_VALIDITY_PATH: &str =
    "/prove-intent-and-balance-first-fill-validity";
/// The API path for requesting an `INTENT ONLY VALIDITY` proof
const INTENT_ONLY_VALIDITY_PATH: &str = "/prove-intent-only-validity";
/// The API path for requesting an `INTENT ONLY FIRST FILL VALIDITY` proof
const INTENT_ONLY_FIRST_FILL_VALIDITY_PATH: &str = "/prove-intent-only-first-fill-validity";
/// The API path for requesting a `NEW OUTPUT BALANCE VALIDITY` proof
const NEW_OUTPUT_BALANCE_VALIDITY_PATH: &str = "/prove-new-output-balance-validity";
/// The API path for requesting an `OUTPUT BALANCE VALIDITY` proof
const OUTPUT_BALANCE_VALIDITY_PATH: &str = "/prove-output-balance-validity";
// Settlement proofs
/// The API path for requesting an `INTENT AND BALANCE BOUNDED SETTLEMENT` proof
const INTENT_AND_BALANCE_BOUNDED_SETTLEMENT_PATH: &str =
    "/prove-intent-and-balance-bounded-settlement";
/// The API path for requesting an `INTENT AND BALANCE PRIVATE SETTLEMENT` proof
const INTENT_AND_BALANCE_PRIVATE_SETTLEMENT_PATH: &str =
    "/prove-intent-and-balance-private-settlement";
/// The API path for requesting an `INTENT AND BALANCE PUBLIC SETTLEMENT` proof
const INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_PATH: &str =
    "/prove-intent-and-balance-public-settlement";
/// The API path for requesting an `INTENT ONLY BOUNDED SETTLEMENT` proof
const INTENT_ONLY_BOUNDED_SETTLEMENT_PATH: &str = "/prove-intent-only-bounded-settlement";
/// The API path for requesting an `INTENT ONLY PUBLIC SETTLEMENT` proof
const INTENT_ONLY_PUBLIC_SETTLEMENT_PATH: &str = "/prove-intent-only-public-settlement";
// Fee proofs
/// The API path for requesting a `VALID NOTE REDEMPTION` proof
const VALID_NOTE_REDEMPTION_PATH: &str = "/prove-valid-note-redemption";
/// The API path for requesting a `VALID PRIVATE PROTOCOL FEE PAYMENT` proof
const VALID_PRIVATE_PROTOCOL_FEE_PAYMENT_PATH: &str = "/prove-valid-private-protocol-fee-payment";
/// The API path for requesting a `VALID PRIVATE RELAYER FEE PAYMENT` proof
const VALID_PRIVATE_RELAYER_FEE_PAYMENT_PATH: &str = "/prove-valid-private-relayer-fee-payment";
/// The API path for requesting a `VALID PUBLIC PROTOCOL FEE PAYMENT` proof
const VALID_PUBLIC_PROTOCOL_FEE_PAYMENT_PATH: &str = "/prove-valid-public-protocol-fee-payment";
/// The API path for requesting a `VALID PUBLIC RELAYER FEE PAYMENT` proof
const VALID_PUBLIC_RELAYER_FEE_PAYMENT_PATH: &str = "/prove-valid-public-relayer-fee-payment";

// ----------
// | Client |
// ----------

/// A client for the proof service
#[derive(Clone)]
pub(crate) struct ProofServiceClient {
    /// The HTTP client to use for connecting to the prover service
    client: Client,
    /// The base URL of the prover service (without trailing slash)
    url: String,
    /// The password for the prover service
    password: String,
}

impl ProofServiceClient {
    /// Create a new proof service client
    pub fn new(config: &ProofManagerConfig) -> Result<Self, ProofManagerError> {
        let client = Client::new();
        let url = config
            .prover_service_url
            .as_ref()
            .ok_or(ProofManagerError::setup("no prover service URL provided"))?
            .as_str()
            .trim_end_matches('/')
            .to_string();
        let password = config
            .prover_service_password
            .clone()
            .ok_or(ProofManagerError::setup("no prover service password provided"))?;

        Ok(Self { client, url, password })
    }

    // --- HTTP Helpers --- //

    /// Send a request to the prover service
    async fn send_request<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        req: Req,
    ) -> Result<Resp, ProofManagerError> {
        // Add the auth header
        let mut headers = HeaderMap::new();
        let cred = Credentials::new(HTTP_BASIC_AUTH_USER, &self.password);
        let header = cred.as_http_header();
        let auth_header = HeaderValue::from_str(&header).map_err(ProofManagerError::http)?;
        headers.insert(AUTHORIZATION, auth_header);

        // Inject tracing propagation headers from the current span
        add_trace_context_to_headers(&mut headers);

        // Build the URL and send the request
        let full_path = format!("{}{path}", self.url);
        let resp = self.client.post(full_path).json(&req).headers(headers).send().await?;
        let res = resp.json::<Resp>().await?;
        Ok(res)
    }

    // --- Prover Methods --- //

    // Update proofs
    /// Request a `VALID BALANCE CREATE` proof from the prover service
    pub(crate) async fn prove_valid_balance_create(
        &self,
        witness: ValidBalanceCreateWitness,
        statement: ValidBalanceCreateStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidBalanceCreateRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_BALANCE_CREATE_PATH, req).await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidBalanceCreate(bundle))
    }

    /// Request a `VALID DEPOSIT` proof from the prover service
    pub(crate) async fn prove_valid_deposit(
        &self,
        witness: SizedValidDepositWitness,
        statement: ValidDepositStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidDepositRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_DEPOSIT_PATH, req).await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidDeposit(bundle))
    }

    /// Request a `VALID ORDER CANCELLATION` proof from the prover service
    pub(crate) async fn prove_valid_order_cancellation(
        &self,
        witness: SizedValidOrderCancellationWitness,
        statement: ValidOrderCancellationStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidOrderCancellationRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_ORDER_CANCELLATION_PATH, req).await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidOrderCancellation(bundle))
    }

    /// Request a `VALID WITHDRAWAL` proof from the prover service
    pub(crate) async fn prove_valid_withdrawal(
        &self,
        witness: SizedValidWithdrawalWitness,
        statement: ValidWithdrawalStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidWithdrawalRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_WITHDRAWAL_PATH, req).await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidWithdrawal(bundle))
    }

    // Validity proofs
    /// Request an `INTENT AND BALANCE VALIDITY` proof from the prover service
    pub(crate) async fn prove_intent_and_balance_validity(
        &self,
        witness: SizedIntentAndBalanceValidityWitness,
        statement: IntentAndBalanceValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentAndBalanceValidityRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofAndHintResponse>(INTENT_AND_BALANCE_VALIDITY_PATH, req)
            .await?;
        let bundle = ProofAndHintBundle::new(res.proof, statement, res.link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceValidity(bundle))
    }

    /// Request an `INTENT AND BALANCE FIRST FILL VALIDITY` proof from the
    /// prover service
    pub(crate) async fn prove_intent_and_balance_first_fill_validity(
        &self,
        witness: SizedIntentAndBalanceFirstFillValidityWitness,
        statement: IntentAndBalanceFirstFillValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req =
            IntentAndBalanceFirstFillValidityRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofAndHintResponse>(
                INTENT_AND_BALANCE_FIRST_FILL_VALIDITY_PATH,
                req,
            )
            .await?;
        let bundle = ProofAndHintBundle::new(res.proof, statement, res.link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceFirstFillValidity(bundle))
    }

    /// Request an `INTENT ONLY VALIDITY` proof from the prover service
    pub(crate) async fn prove_intent_only_validity(
        &self,
        witness: SizedIntentOnlyValidityWitness,
        statement: IntentOnlyValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentOnlyValidityRequest { statement: statement.clone(), witness };
        let res =
            self.send_request::<_, ProofAndHintResponse>(INTENT_ONLY_VALIDITY_PATH, req).await?;
        let bundle = ProofAndHintBundle::new(res.proof, statement, res.link_hint);
        Ok(ProofManagerResponse::IntentOnlyValidity(bundle))
    }

    /// Request an `INTENT ONLY FIRST FILL VALIDITY` proof from the prover
    /// service
    pub(crate) async fn prove_intent_only_first_fill_validity(
        &self,
        witness: IntentOnlyFirstFillValidityWitness,
        statement: IntentOnlyFirstFillValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentOnlyFirstFillValidityRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofAndHintResponse>(INTENT_ONLY_FIRST_FILL_VALIDITY_PATH, req)
            .await?;
        let bundle = ProofAndHintBundle::new(res.proof, statement, res.link_hint);
        Ok(ProofManagerResponse::IntentOnlyFirstFillValidity(bundle))
    }

    /// Request a `NEW OUTPUT BALANCE VALIDITY` proof from the prover service
    pub(crate) async fn prove_new_output_balance_validity(
        &self,
        witness: SizedNewOutputBalanceValidityWitness,
        statement: NewOutputBalanceValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = NewOutputBalanceValidityRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofAndHintResponse>(NEW_OUTPUT_BALANCE_VALIDITY_PATH, req)
            .await?;
        let bundle = ProofAndHintBundle::new(res.proof, statement, res.link_hint);
        Ok(ProofManagerResponse::NewOutputBalanceValidity(bundle))
    }

    /// Request an `OUTPUT BALANCE VALIDITY` proof from the prover service
    pub(crate) async fn prove_output_balance_validity(
        &self,
        witness: SizedOutputBalanceValidityWitness,
        statement: OutputBalanceValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = OutputBalanceValidityRequest { statement: statement.clone(), witness };
        let res =
            self.send_request::<_, ProofAndHintResponse>(OUTPUT_BALANCE_VALIDITY_PATH, req).await?;
        let bundle = ProofAndHintBundle::new(res.proof, statement, res.link_hint);
        Ok(ProofManagerResponse::OutputBalanceValidity(bundle))
    }

    // Settlement proofs
    /// Request an `INTENT AND BALANCE BOUNDED SETTLEMENT` proof from the prover
    /// service
    pub(crate) async fn prove_intent_and_balance_bounded_settlement(
        &self,
        witness: IntentAndBalanceBoundedSettlementWitness,
        statement: IntentAndBalanceBoundedSettlementStatement,
        validity_link_hint: ProofLinkingHint,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentAndBalanceBoundedSettlementRequest {
            statement: statement.clone(),
            witness,
            validity_link_hint,
        };
        let res = self
            .send_request::<_, SettlementProofResponse>(
                INTENT_AND_BALANCE_BOUNDED_SETTLEMENT_PATH,
                req,
            )
            .await?;
        let bundle = SettlementProofBundle::new(res.proof, statement, res.link_proof);
        Ok(ProofManagerResponse::IntentAndBalanceBoundedSettlement(bundle))
    }

    /// Request an `INTENT AND BALANCE PRIVATE SETTLEMENT` proof from the prover
    /// service
    pub(crate) async fn prove_intent_and_balance_private_settlement(
        &self,
        witness: IntentAndBalancePrivateSettlementWitness,
        statement: IntentAndBalancePrivateSettlementStatement,
        validity_link_hint_0: ProofLinkingHint,
        validity_link_hint_1: ProofLinkingHint,
        output_balance_link_hint_0: ProofLinkingHint,
        output_balance_link_hint_1: ProofLinkingHint,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentAndBalancePrivateSettlementRequest {
            statement: statement.clone(),
            witness,
            validity_link_hint_0,
            validity_link_hint_1,
            output_balance_link_hint_0,
            output_balance_link_hint_1,
        };
        let res = self
            .send_request::<_, PrivateSettlementProofResponse>(
                INTENT_AND_BALANCE_PRIVATE_SETTLEMENT_PATH,
                req,
            )
            .await?;
        let bundle = PrivateSettlementProofBundle::new(
            res.proof,
            statement,
            res.validity_link_proof_0,
            res.validity_link_proof_1,
            res.output_balance_link_proof_0,
            res.output_balance_link_proof_1,
        );
        Ok(ProofManagerResponse::IntentAndBalancePrivateSettlement(bundle))
    }

    /// Request an `INTENT AND BALANCE PUBLIC SETTLEMENT` proof from the prover
    /// service
    pub(crate) async fn prove_intent_and_balance_public_settlement(
        &self,
        witness: IntentAndBalancePublicSettlementWitness,
        statement: IntentAndBalancePublicSettlementStatement,
        party_id: PartyId,
        validity_link_hint: ProofLinkingHint,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentAndBalancePublicSettlementRequest {
            statement: statement.clone(),
            witness,
            party_id: party_id as u8,
            validity_link_hint,
        };
        let res = self
            .send_request::<_, SettlementProofResponse>(
                INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_PATH,
                req,
            )
            .await?;
        let bundle = SettlementProofBundle::new(res.proof, statement, res.link_proof);
        Ok(ProofManagerResponse::IntentAndBalancePublicSettlement(bundle))
    }

    /// Request an `INTENT ONLY BOUNDED SETTLEMENT` proof from the prover
    /// service
    pub(crate) async fn prove_intent_only_bounded_settlement(
        &self,
        witness: IntentOnlyBoundedSettlementWitness,
        statement: IntentOnlyBoundedSettlementStatement,
        validity_link_hint: ProofLinkingHint,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentOnlyBoundedSettlementRequest {
            statement: statement.clone(),
            witness,
            validity_link_hint,
        };
        let res = self
            .send_request::<_, SettlementProofResponse>(INTENT_ONLY_BOUNDED_SETTLEMENT_PATH, req)
            .await?;
        let bundle = SettlementProofBundle::new(res.proof, statement, res.link_proof);
        Ok(ProofManagerResponse::IntentOnlyBoundedSettlement(bundle))
    }

    /// Request an `INTENT ONLY PUBLIC SETTLEMENT` proof from the prover service
    pub(crate) async fn prove_intent_only_public_settlement(
        &self,
        witness: IntentOnlyPublicSettlementWitness,
        statement: IntentOnlyPublicSettlementStatement,
        validity_link_hint: ProofLinkingHint,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = IntentOnlyPublicSettlementRequest {
            statement: statement.clone(),
            witness,
            validity_link_hint,
        };
        let res = self
            .send_request::<_, SettlementProofResponse>(INTENT_ONLY_PUBLIC_SETTLEMENT_PATH, req)
            .await?;
        let bundle = SettlementProofBundle::new(res.proof, statement, res.link_proof);
        Ok(ProofManagerResponse::IntentOnlyPublicSettlement(bundle))
    }

    // Fee proofs
    /// Request a `VALID NOTE REDEMPTION` proof from the prover service
    pub(crate) async fn prove_valid_note_redemption(
        &self,
        witness: SizedValidNoteRedemptionWitness,
        statement: ValidNoteRedemptionStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidNoteRedemptionRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_NOTE_REDEMPTION_PATH, req).await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidNoteRedemption(bundle))
    }

    /// Request a `VALID PRIVATE PROTOCOL FEE PAYMENT` proof from the prover
    /// service
    pub(crate) async fn prove_valid_private_protocol_fee_payment(
        &self,
        witness: SizedValidPrivateProtocolFeePaymentWitness,
        statement: ValidPrivateProtocolFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidPrivateProtocolFeePaymentRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofResponse>(VALID_PRIVATE_PROTOCOL_FEE_PAYMENT_PATH, req)
            .await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidPrivateProtocolFeePayment(bundle))
    }

    /// Request a `VALID PRIVATE RELAYER FEE PAYMENT` proof from the prover
    /// service
    pub(crate) async fn prove_valid_private_relayer_fee_payment(
        &self,
        witness: SizedValidPrivateRelayerFeePaymentWitness,
        statement: ValidPrivateRelayerFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidPrivateRelayerFeePaymentRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofResponse>(VALID_PRIVATE_RELAYER_FEE_PAYMENT_PATH, req)
            .await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidPrivateRelayerFeePayment(bundle))
    }

    /// Request a `VALID PUBLIC PROTOCOL FEE PAYMENT` proof from the prover
    /// service
    pub(crate) async fn prove_valid_public_protocol_fee_payment(
        &self,
        witness: SizedValidPublicProtocolFeePaymentWitness,
        statement: ValidPublicProtocolFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidPublicProtocolFeePaymentRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofResponse>(VALID_PUBLIC_PROTOCOL_FEE_PAYMENT_PATH, req)
            .await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidPublicProtocolFeePayment(bundle))
    }

    /// Request a `VALID PUBLIC RELAYER FEE PAYMENT` proof from the prover
    /// service
    pub(crate) async fn prove_valid_public_relayer_fee_payment(
        &self,
        witness: SizedValidPublicRelayerFeePaymentWitness,
        statement: ValidPublicRelayerFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let req = ValidPublicRelayerFeePaymentRequest { statement: statement.clone(), witness };
        let res = self
            .send_request::<_, ProofResponse>(VALID_PUBLIC_RELAYER_FEE_PAYMENT_PATH, req)
            .await?;
        let bundle = ProofBundle::new(res.proof, statement);
        Ok(ProofManagerResponse::ValidPublicRelayerFeePayment(bundle))
    }
}
