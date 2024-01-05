//! Defines a mock for the proof manager that doesn't prove statements, but
//! instead immediately returns dummy proofs that will not verify

use circuit_types::traits::SingleProverCircuit;
use circuits::zk_circuits::{
    check_constraint_satisfaction,
    valid_commitments::{
        SizedValidCommitments, SizedValidCommitmentsWitness, ValidCommitmentsStatement,
    },
    valid_match_settle::{
        SizedValidMatchSettle, SizedValidMatchSettleStatement, SizedValidMatchSettleWitness,
    },
    valid_reblind::{SizedValidReblind, SizedValidReblindWitness, ValidReblindStatement},
    valid_wallet_create::{
        SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    },
    valid_wallet_update::{
        SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
    },
};
use common::types::proof_bundles::{
    mocks::dummy_proof, GenericMatchSettleBundle, GenericValidCommitmentsBundle,
    GenericValidReblindBundle, GenericValidWalletCreateBundle, GenericValidWalletUpdateBundle,
    ProofBundle, ValidCommitmentsBundle, ValidMatchSettleBundle, ValidReblindBundle,
    ValidWalletCreateBundle, ValidWalletUpdateBundle,
};
use crossbeam::channel::Receiver;
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use tokio::{runtime::Handle, sync::oneshot::Sender as TokioSender};
use tracing::log;

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
    pub fn start(job_queue: Receiver<ProofManagerJob>) {
        Handle::current().spawn_blocking(move || {
            if let Err(e) = Self::execution_loop(&job_queue) {
                log::error!("error in mock proof manager: {e}");
            }
        });
    }

    /// The execution loop for the mock
    fn execution_loop(job_queue: &Receiver<ProofManagerJob>) -> Result<(), ProofManagerError> {
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
                ProofBundle::ValidWalletCreate(Self::valid_wallet_create(witness, statement)?)
            },
            ProofJob::ValidWalletUpdate { witness, statement } => {
                ProofBundle::ValidWalletUpdate(Self::valid_wallet_update(witness, statement)?)
            },
            ProofJob::ValidReblind { witness, statement } => {
                ProofBundle::ValidReblind(Self::valid_reblind(witness, statement)?)
            },
            ProofJob::ValidCommitments { witness, statement } => {
                ProofBundle::ValidCommitments(Self::valid_commitments(witness, statement)?)
            },
            ProofJob::ValidMatchSettleSingleprover { witness, statement } => {
                ProofBundle::ValidMatchSettle(Self::valid_match_settle(witness, statement)?)
            },
        };

        response_channel.send(bundle).expect(ERR_RESPONSE_CHANNEL_CLOSED);
        Ok(())
    }

    /// Generate a dummy proof of `VALID WALLET CREATE`
    fn valid_wallet_create(
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> Result<ValidWalletCreateBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidWalletCreate>(&witness, &statement)?;

        let proof = dummy_proof();
        Ok(Box::new(GenericValidWalletCreateBundle { statement, proof }))
    }

    /// Generate a dummy proof of `VALID WALLET UPDATE`
    fn valid_wallet_update(
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> Result<ValidWalletUpdateBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidWalletUpdate>(&witness, &statement)?;

        let proof = dummy_proof();
        Ok(Box::new(GenericValidWalletUpdateBundle { statement, proof }))
    }

    /// Generate a dummy proof of `VALID REBLIND`
    fn valid_reblind(
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> Result<ValidReblindBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidReblind>(&witness, &statement)?;

        let proof = dummy_proof();
        Ok(Box::new(GenericValidReblindBundle { statement, proof }))
    }

    /// Create a dummy proof of `VALID COMMITMENTS`
    fn valid_commitments(
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ValidCommitmentsBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidCommitments>(&witness, &statement)?;

        let proof = dummy_proof();
        Ok(Box::new(GenericValidCommitmentsBundle { statement, proof }))
    }

    /// Create a dummy proof of `VALID MATCH SETTLE`
    fn valid_match_settle(
        witness: SizedValidMatchSettleWitness,
        statement: SizedValidMatchSettleStatement,
    ) -> Result<ValidMatchSettleBundle, ProofManagerError> {
        Self::check_constraints::<SizedValidMatchSettle>(&witness, &statement)?;

        let proof = dummy_proof();
        Ok(Box::new(GenericMatchSettleBundle { statement, proof }))
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
