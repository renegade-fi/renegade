//! Implements the client for the prover service

use circuit_types::ProofLinkingHint;
use circuits::zk_circuits::{
    valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
    valid_fee_redemption::{SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness},
    valid_malleable_match_settle_atomic::{
        SizedValidMalleableMatchSettleAtomicStatement, SizedValidMalleableMatchSettleAtomicWitness,
    },
    valid_match_settle::{SizedValidMatchSettleStatement, SizedValidMatchSettleWitness},
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomicStatement, SizedValidMatchSettleAtomicWitness,
    },
    valid_offline_fee_settlement::{
        SizedValidOfflineFeeSettlementStatement, SizedValidOfflineFeeSettlementWitness,
    },
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
    valid_wallet_create::{SizedValidWalletCreateStatement, SizedValidWalletCreateWitness},
    valid_wallet_update::{SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness},
};
use common::types::proof_bundles::ProofBundle;
use http_auth_basic::Credentials;
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::ProofManagerError,
    implementations::external_proof_manager::api_types::{
        LinkCommitmentsReblindRequest, ProofAndHintResponse, ProofAndLinkResponse,
        ProofLinkResponse, ProofResponse, ValidCommitmentsRequest, ValidFeeRedemptionRequest,
        ValidMalleableMatchSettleAtomicRequest, ValidMatchSettleAtomicRequest,
        ValidMatchSettleRequest, ValidMatchSettleResponse, ValidOfflineFeeSettlementRequest,
        ValidReblindRequest, ValidWalletCreateRequest, ValidWalletUpdateRequest,
    },
    worker::ProofManagerConfig,
};

/// The HTTP basic auth user name to use
const HTTP_BASIC_AUTH_USER: &str = "admin";

// ---------
// | Paths |
// ---------

/// The path at which to request a `VALID WALLET CREATE` proof
const VALID_WALLET_CREATE_PATH: &str = "prove-valid-wallet-create";
/// The path at which to request a `VALID WALLET UPDATE` proof
const VALID_WALLET_UPDATE_PATH: &str = "prove-valid-wallet-update";
/// The path at which to request a `VALID COMMITMENTS` proof
const VALID_COMMITMENTS_PATH: &str = "prove-valid-commitments";
/// The path at which to request a `VALID REBLIND` proof
const VALID_REBLIND_PATH: &str = "prove-valid-reblind";
/// The path at which to link commitments and reblind
const LINK_COMMITMENTS_REBLIND_PATH: &str = "link-commitments-reblind";
/// The path at which to request a `VALID MATCH SETTLE` proof
const VALID_MATCH_SETTLE_PATH: &str = "prove-valid-match-settle";
/// The path at which to request a `VALID MATCH SETTLE ATOMIC` proof
const VALID_MATCH_SETTLE_ATOMIC_PATH: &str = "prove-valid-match-settle-atomic";
/// The path at which to request a `VALID MALLEABLE MATCH SETTLE ATOMIC` proof
const VALID_MALLEABLE_MATCH_SETTLE_ATOMIC_PATH: &str = "prove-valid-malleable-match-settle-atomic";
/// The path at which to request a `VALID FEE REDEMPTION` proof
const VALID_FEE_REDEMPTION_PATH: &str = "prove-valid-fee-redemption";
/// The path at which to request a `VALID OFFLINE FEE SETTLEMENT` proof
const VALID_OFFLINE_FEE_SETTLEMENT_PATH: &str = "prove-valid-offline-fee-settlement";

// ----------
// | Client |
// ----------

/// A client for the proof service
#[derive(Clone)]
pub(crate) struct ProofServiceClient {
    /// The HTTP client to use for connecting to the prover service
    client: Client,
    /// The URL of the prover service
    url: Url,
    /// The password for the prover service
    password: String,
}

impl ProofServiceClient {
    /// Create a new proof service client
    pub fn new(config: &ProofManagerConfig) -> Result<Self, ProofManagerError> {
        let client = Client::new();
        let url = config
            .prover_service_url
            .clone()
            .ok_or(ProofManagerError::setup("no prover service URL provided"))?;
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

        // Build the URL and send the request
        let full_path = format!("{}{path}", self.url);
        let resp = self.client.post(full_path).json(&req).headers(headers).send().await?;
        let res = resp.json::<Resp>().await?;
        Ok(res)
    }

    // --- Prover Methods --- //

    /// Request a `VALID WALLET CREATE` proof from the prover service
    pub(crate) async fn prove_valid_wallet_create(
        &self,
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidWalletCreateRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_WALLET_CREATE_PATH, req).await?;

        let bundle = ProofBundle::new_valid_wallet_create(statement, res.proof);
        Ok(bundle)
    }

    /// Request a `VALID WALLET UPDATE` proof from the prover service
    pub(crate) async fn prove_valid_wallet_update(
        &self,
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidWalletUpdateRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_WALLET_UPDATE_PATH, req).await?;

        let bundle = ProofBundle::new_valid_wallet_update(statement, res.proof);
        Ok(bundle)
    }

    /// Request a `VALID COMMITMENTS` proof from the prover service
    pub(crate) async fn prove_valid_commitments(
        &self,
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidCommitmentsRequest { statement, witness };
        let res = self.send_request::<_, ProofAndHintResponse>(VALID_COMMITMENTS_PATH, req).await?;

        let bundle = ProofBundle::new_valid_commitments(statement, res.proof, res.link_hint);
        Ok(bundle)
    }

    /// Request a `VALID REBLIND` proof from the prover service
    pub(crate) async fn prove_valid_reblind(
        &self,
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidReblindRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofAndHintResponse>(VALID_REBLIND_PATH, req).await?;

        let bundle = ProofBundle::new_valid_reblind(statement, res.proof, res.link_hint);
        Ok(bundle)
    }

    /// Request a `VALID COMMITMENTS` <-> `VALID REBLIND` proof link from the
    /// prover service
    pub(crate) async fn prove_valid_commitments_reblind_link(
        &self,
        commitments_hint: ProofLinkingHint,
        reblind_hint: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Request the prover service
        let req = LinkCommitmentsReblindRequest {
            valid_commitments_hint: commitments_hint,
            valid_reblind_hint: reblind_hint,
        };
        let res =
            self.send_request::<_, ProofLinkResponse>(LINK_COMMITMENTS_REBLIND_PATH, req).await?;

        // Build the proof bundle
        let bundle = ProofBundle::new_valid_commitments_reblind_link(res.link_proof);
        Ok(bundle)
    }

    /// Request a `VALID MATCH SETTLE` proof from the prover service
    pub(crate) async fn prove_valid_match_settle(
        &self,
        witness: SizedValidMatchSettleWitness,
        statement: SizedValidMatchSettleStatement,
        commitment_link0: ProofLinkingHint,
        commitment_link1: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidMatchSettleRequest {
            statement: statement.clone(),
            witness,
            valid_commitments_hint0: commitment_link0,
            valid_commitments_hint1: commitment_link1,
        };
        let res =
            self.send_request::<_, ValidMatchSettleResponse>(VALID_MATCH_SETTLE_PATH, req).await?;

        let bundle = ProofBundle::new_valid_match_settle(
            statement,
            res.plonk_proof,
            res.link_proof0,
            res.link_proof1,
        );
        Ok(bundle)
    }

    /// Request a `VALID MATCH SETTLE ATOMIC` proof from the prover service
    pub(crate) async fn prove_valid_match_settle_atomic(
        &self,
        witness: SizedValidMatchSettleAtomicWitness,
        statement: SizedValidMatchSettleAtomicStatement,
        commitments_link: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Request the prover service
        let req = ValidMatchSettleAtomicRequest {
            statement: statement.clone(),
            witness,
            valid_commitments_hint: commitments_link,
        };
        let res = self
            .send_request::<_, ProofAndLinkResponse>(VALID_MATCH_SETTLE_ATOMIC_PATH, req)
            .await?;

        // Build the proof bundle
        let bundle =
            ProofBundle::new_valid_match_settle_atomic(statement, res.plonk_proof, res.link_proof);
        Ok(bundle)
    }

    /// Request a `VALID MALLEABLE MATCH SETTLE ATOMIC` proof from the prover
    /// service
    pub(crate) async fn prove_valid_malleable_match_settle_atomic(
        &self,
        witness: SizedValidMalleableMatchSettleAtomicWitness,
        statement: SizedValidMalleableMatchSettleAtomicStatement,
        commitments_link: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Request the prover service
        let req = ValidMalleableMatchSettleAtomicRequest {
            statement: statement.clone(),
            witness,
            valid_commitments_hint: commitments_link,
        };
        let res = self
            .send_request::<_, ProofAndLinkResponse>(VALID_MALLEABLE_MATCH_SETTLE_ATOMIC_PATH, req)
            .await?;

        // Build the proof bundle
        let bundle = ProofBundle::new_valid_malleable_match_settle_atomic(
            statement,
            res.plonk_proof,
            res.link_proof,
        );
        Ok(bundle)
    }

    /// Request a `VALID FEE REDEMPTION` proof from the prover service
    pub(crate) async fn prove_valid_fee_redemption(
        &self,
        witness: SizedValidFeeRedemptionWitness,
        statement: SizedValidFeeRedemptionStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidFeeRedemptionRequest { statement: statement.clone(), witness };
        let res = self.send_request::<_, ProofResponse>(VALID_FEE_REDEMPTION_PATH, req).await?;

        let bundle = ProofBundle::new_valid_fee_redemption(statement, res.proof);
        Ok(bundle)
    }

    /// Request a `VALID OFFLINE FEE SETTLEMENT` proof from the prover service
    pub(crate) async fn prove_valid_offline_fee_settlement(
        &self,
        witness: SizedValidOfflineFeeSettlementWitness,
        statement: SizedValidOfflineFeeSettlementStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        let req = ValidOfflineFeeSettlementRequest { statement: statement.clone(), witness };
        let res =
            self.send_request::<_, ProofResponse>(VALID_OFFLINE_FEE_SETTLEMENT_PATH, req).await?;

        let bundle = ProofBundle::new_valid_offline_fee_settlement(statement, res.proof);
        Ok(bundle)
    }
}
