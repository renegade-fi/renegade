//! Defines a mock for the proof manager that doesn't prove statements, but
//! instead immediately returns dummy proofs that will not verify

use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    check_constraint_satisfaction,
    valid_commitments::{
        SizedValidCommitments, SizedValidCommitmentsWitness, ValidCommitmentsStatement,
    },
    valid_fee_redemption::{
        SizedValidFeeRedemption, SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness,
    },
    valid_match_settle::{
        SizedValidMatchSettle, SizedValidMatchSettleStatement, SizedValidMatchSettleWitness,
    },
    valid_match_settle_atomic::{
        SizedValidMatchSettleAtomic, SizedValidMatchSettleAtomicStatement,
        SizedValidMatchSettleAtomicWitness,
    },
    valid_offline_fee_settlement::{
        SizedValidOfflineFeeSettlement, SizedValidOfflineFeeSettlementStatement,
        SizedValidOfflineFeeSettlementWitness,
    },
    valid_reblind::{SizedValidReblind, SizedValidReblindWitness, ValidReblindStatement},
    valid_relayer_fee_settlement::{
        SizedValidRelayerFeeSettlement, SizedValidRelayerFeeSettlementStatement,
        SizedValidRelayerFeeSettlementWitness,
    },
    valid_wallet_create::{
        SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    },
    valid_wallet_update::{
        SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
    },
};
use common::types::proof_bundles::{
    mocks::{dummy_link_hint, dummy_proof},
    ProofBundle,
};
use job_types::proof_manager::{ProofJob, ProofManagerReceiver};
use tokio::{runtime::Handle, sync::oneshot::Sender as TokioSender};
use tracing::error;

use crate::error::ProofManagerError;

/// The error message emitted when a response channel closes early
const ERR_RESPONSE_CHANNEL_CLOSED: &str = "error sending proof, channel closed";

// -----------
// | Helpers |
// -----------

/// The mock proof manager
pub struct MockProofManager;
#[allow(clippy::needless_pass_by_value)]
impl MockProofManager {
    /// Start a mock proof manager
    pub fn start(job_queue: ProofManagerReceiver) {
        Handle::current().spawn_blocking(move || {
            if let Err(e) = Self::execution_loop(&job_queue) {
                error!("error in mock proof manager: {e}");
            }
        });
    }

    /// The execution loop for the mock
    fn execution_loop(job_queue: &ProofManagerReceiver) -> Result<(), ProofManagerError> {
        loop {
            match job_queue.recv() {
                Err(_) => {
                    return Err(ProofManagerError::JobQueueClosed("job queue closed".to_string()));
                },
                Ok(job) => Self::handle_job(job.type_, job.response_channel)?,
            }
        }
    }

    /// Handle a job by immediately returning a dummy proof
    fn handle_job(
        job_type: ProofJob,
        response_channel: TokioSender<ProofBundle>,
    ) -> Result<(), ProofManagerError> {
        let bundle = match job_type {
            ProofJob::ValidWalletCreate { witness, statement } => {
                Self::valid_wallet_create(witness, statement)
            },
            ProofJob::ValidWalletUpdate { witness, statement } => {
                Self::valid_wallet_update(witness, statement)
            },
            ProofJob::ValidReblind { witness, statement } => {
                Self::valid_reblind(witness, statement)
            },
            ProofJob::ValidCommitments { witness, statement } => {
                Self::valid_commitments(witness, statement)
            },
            ProofJob::ValidMatchSettleSingleprover { witness, statement } => {
                Self::valid_match_settle(witness, statement)
            },
            ProofJob::ValidMatchSettleAtomic { witness, statement } => {
                Self::valid_match_settle_atomic(witness, statement)
            },
            ProofJob::ValidRelayerFeeSettlement { witness, statement } => {
                Self::valid_relayer_fee_settlement(witness, statement)
            },
            ProofJob::ValidOfflineFeeSettlement { witness, statement } => {
                Self::valid_offline_fee_settlement(witness, statement)
            },
            ProofJob::ValidFeeRedemption { witness, statement } => {
                Self::valid_fee_redemption(witness, statement)
            },
        }?;

        response_channel.send(bundle).expect(ERR_RESPONSE_CHANNEL_CLOSED);
        Ok(())
    }

    /// Generate a dummy proof of `VALID WALLET CREATE`
    fn valid_wallet_create(
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidWalletCreate>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_wallet_create(statement, proof, link_hint))
    }

    /// Generate a dummy proof of `VALID WALLET UPDATE`
    fn valid_wallet_update(
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidWalletUpdate>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_wallet_update(statement, proof, link_hint))
    }

    /// Generate a dummy proof of `VALID REBLIND`
    fn valid_reblind(
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidReblind>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_reblind(statement, proof, link_hint))
    }

    /// Create a dummy proof of `VALID COMMITMENTS`
    fn valid_commitments(
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidCommitments>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_commitments(statement, proof, link_hint))
    }

    /// Create a dummy proof of `VALID MATCH SETTLE`
    fn valid_match_settle(
        witness: SizedValidMatchSettleWitness,
        statement: SizedValidMatchSettleStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidMatchSettle>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_match_settle(statement, proof, link_hint))
    }

    /// Create a dummy proof of `VALID MATCH SETTLE ATOMIC`
    fn valid_match_settle_atomic(
        witness: SizedValidMatchSettleAtomicWitness,
        statement: SizedValidMatchSettleAtomicStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidMatchSettleAtomic>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_match_settle_atomic(statement, proof, link_hint))
    }

    /// Generate a dummy proof of `VALID RELAYER FEE SETTLEMENT`
    fn valid_relayer_fee_settlement(
        witness: SizedValidRelayerFeeSettlementWitness,
        statement: SizedValidRelayerFeeSettlementStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidRelayerFeeSettlement>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_relayer_fee_settlement(statement, proof, link_hint))
    }

    /// Generate a dummy proof of `VALID OFFLINE FEE SETTLEMENT`
    fn valid_offline_fee_settlement(
        witness: SizedValidOfflineFeeSettlementWitness,
        statement: SizedValidOfflineFeeSettlementStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidOfflineFeeSettlement>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_offline_fee_settlement(statement, proof, link_hint))
    }

    /// Generate a dummy proof of `VALID FEE REDEMPTION`
    fn valid_fee_redemption(
        witness: SizedValidFeeRedemptionWitness,
        statement: SizedValidFeeRedemptionStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidFeeRedemption>(&witness, &statement)?;

        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        Ok(ProofBundle::new_valid_fee_redemption(statement, proof, link_hint))
    }

    /// Check constraint satisfaction for a witness and statement
    ///
    /// This helper effectively wraps a boolean in the error type needed by the
    /// interface
    fn check_constraints<C: SingleProverCircuit>(
        witness: &C::Witness,
        statement: &C::Statement,
    ) -> Result<(), ProofManagerError> {
        if !check_constraint_satisfaction::<C>(witness, statement) {
            let err = format!("invalid witness and statement for {}", C::name());
            Err(ProofManagerError::Prover(err))
        } else {
            Ok(())
        }
    }
}
