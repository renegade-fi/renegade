//! Defines a mock for the proof manager that doesn't prove statements, but
//! instead immediately returns dummy proofs that will not verify

use circuits::zk_circuits::{
    valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
    valid_match_settle::{SizedValidMatchSettleStatement, SizedValidMatchSettleWitness},
    valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
    valid_wallet_create::{SizedValidWalletCreateStatement, SizedValidWalletCreateWitness},
    valid_wallet_update::{SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness},
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

/// The error emitted when the job queue closes early
const ERR_JOB_QUEUE_CLOSED: &str = "error receiving job, channel closed";
/// The error message emitted when a response channel closes early
const ERR_RESPONSE_CHANNEL_CLOSED: &str = "error sending proof, channel closed";

// -----------
// | Helpers |
// -----------

/// The mock proof manager
pub struct MockProofManager;
impl MockProofManager {
    /// Start a mock proof manager
    pub fn start(job_queue: Receiver<ProofManagerJob>) {
        Handle::current().spawn_blocking(move || Self::execution_loop(job_queue));
    }

    /// The execution loop for the mock
    fn execution_loop(job_queue: Receiver<ProofManagerJob>) {
        loop {
            let job = job_queue.recv().expect(ERR_JOB_QUEUE_CLOSED);
            Self::handle_job(job.type_, job.response_channel);
        }
    }

    /// Handle a job by immediately returning a dummy proof
    fn handle_job(job_type: ProofJob, response_channel: TokioSender<ProofBundle>) {
        let bundle = match job_type {
            ProofJob::ValidWalletCreate { witness, statement } => {
                ProofBundle::ValidWalletCreate(Self::valid_wallet_create(witness, statement))
            },
            ProofJob::ValidWalletUpdate { witness, statement } => {
                ProofBundle::ValidWalletUpdate(Self::valid_wallet_update(witness, statement))
            },
            ProofJob::ValidReblind { witness, statement } => {
                ProofBundle::ValidReblind(Self::valid_reblind(witness, statement))
            },
            ProofJob::ValidCommitments { witness, statement } => {
                ProofBundle::ValidCommitments(Self::valid_commitments(witness, statement))
            },
            ProofJob::ValidMatchSettleSingleprover { witness, statement } => {
                ProofBundle::ValidMatchSettle(Self::valid_match_settle(witness, statement))
            },
        };

        response_channel.send(bundle).expect(ERR_RESPONSE_CHANNEL_CLOSED);
    }

    /// Generate a dummy proof of `VALID WALLET CREATE`
    fn valid_wallet_create(
        _witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> ValidWalletCreateBundle {
        let proof = dummy_proof();
        Box::new(GenericValidWalletCreateBundle { statement, proof })
    }

    /// Generate a dummy proof of `VALID WALLET UPDATE`
    fn valid_wallet_update(
        _witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> ValidWalletUpdateBundle {
        let proof = dummy_proof();
        Box::new(GenericValidWalletUpdateBundle { statement, proof })
    }

    /// Generate a dummy proof of `VALID REBLIND`
    fn valid_reblind(
        _witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> ValidReblindBundle {
        let proof = dummy_proof();
        Box::new(GenericValidReblindBundle { statement, proof })
    }

    /// Create a dummy proof of `VALID COMMITMENTS`
    fn valid_commitments(
        _witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> ValidCommitmentsBundle {
        let proof = dummy_proof();
        Box::new(GenericValidCommitmentsBundle { statement, proof })
    }

    /// Create a dummy proof of `VALID MATCH SETTLE`
    fn valid_match_settle(
        _witness: SizedValidMatchSettleWitness,
        statement: SizedValidMatchSettleStatement,
    ) -> ValidMatchSettleBundle {
        let proof = dummy_proof();
        Box::new(GenericMatchSettleBundle { statement, proof })
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use circuit_types::{traits::BaseType, wallet::WalletShare};
    use circuits::zk_circuits::valid_wallet_create::{
        SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    };
    use constants::Scalar;
    use crossbeam::channel::unbounded;
    use job_types::proof_manager::{ProofJob, ProofManagerJob};
    use tokio::{runtime::Builder as RuntimeBuilder, sync::oneshot::channel as oneshot_channel};

    use super::MockProofManager;

    /// Test the spawning and execution of a mock proof manager
    #[tokio::test]
    async fn test_simple_proof() {
        // Create a runtime to manage spawn the mock within
        let runtime = RuntimeBuilder::new_current_thread().enable_all().build().unwrap();

        let (job_send, job_recv) = unbounded();
        runtime.spawn_blocking(move || MockProofManager::start(job_recv));

        // Create a dummy witness and statement
        let witness = SizedValidWalletCreateWitness {
            private_wallet_share: WalletShare::from_scalars(&mut iter::repeat(Scalar::zero())),
        };
        let statement = SizedValidWalletCreateStatement {
            public_wallet_shares: WalletShare::from_scalars(&mut iter::repeat(Scalar::zero())),
            private_shares_commitment: Scalar::zero(),
        };

        // Send a job to the mock and expect a mock proof back
        let (response_send, response_recv) = oneshot_channel();
        job_send
            .send(ProofManagerJob {
                response_channel: response_send,
                type_: ProofJob::ValidWalletCreate { witness, statement },
            })
            .unwrap();

        response_recv.await.unwrap();
        runtime.shutdown_background()
    }
}
