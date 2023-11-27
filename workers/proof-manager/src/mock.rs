//! Defines a mock for the proof manager that doesn't prove statements, but
//! instead immediately returns dummy proofs that will not verify

use circuit_types::traits::{CircuitBaseType, SingleProverCircuit};
use circuits::zk_circuits::{
    valid_commitments::{
        SizedValidCommitments, SizedValidCommitmentsWitness, ValidCommitmentsStatement,
    },
    valid_match_mpc::{ValidMatchMpcSingleProver, ValidMatchMpcWitness},
    valid_reblind::{SizedValidReblind, SizedValidReblindWitness, ValidReblindStatement},
    valid_settle::{SizedValidSettle, SizedValidSettleStatement, SizedValidSettleWitness},
    valid_wallet_create::{
        SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    },
    valid_wallet_update::{
        SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
    },
};
use common::types::proof_bundles::{
    GenericValidCommitmentsBundle, GenericValidMatchMpcBundle, GenericValidReblindBundle,
    GenericValidSettleBundle, GenericValidWalletCreateBundle, GenericValidWalletUpdateBundle,
    ProofBundle, ValidCommitmentsBundle, ValidMatchMpcBundle, ValidReblindBundle,
    ValidSettleBundle, ValidWalletCreateBundle, ValidWalletUpdateBundle,
};
use crossbeam::channel::Receiver;
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof},
    InnerProductProof, PedersenGens,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::thread_rng;
use tokio::{runtime::Handle, sync::oneshot::Sender as TokioSender};

/// The error emitted when the job queue closes early
const ERR_JOB_QUEUE_CLOSED: &str = "error receiving job, channel closed";
/// The error message emitted when a response channel closes early
const ERR_RESPONSE_CHANNEL_CLOSED: &str = "error sending proof, channel closed";

// -----------
// | Helpers |
// -----------

/// Create a mock constraint system and commit to a witness
fn create_mock_commitment<C: SingleProverCircuit>(
    witness: C::Witness,
) -> <C::Witness as CircuitBaseType>::CommitmentType {
    let mut transcript = Transcript::new(b"mock");
    let pc_gens = PedersenGens::default();
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    let mut rng = thread_rng();
    let (_, comm_type) = witness.commit_witness(&mut rng, &mut prover);

    comm_type
}

/// Create a mock `R1CSProof`
fn create_mock_proof() -> R1CSProof {
    R1CSProof {
        A_I1: StarkPoint::generator(),
        A_O1: StarkPoint::generator(),
        S1: StarkPoint::generator(),
        A_I2: StarkPoint::generator(),
        A_O2: StarkPoint::generator(),
        S2: StarkPoint::generator(),
        T_1: StarkPoint::generator(),
        T_3: StarkPoint::generator(),
        T_4: StarkPoint::generator(),
        T_5: StarkPoint::generator(),
        T_6: StarkPoint::generator(),
        t_x: Scalar::zero(),
        t_x_blinding: Scalar::zero(),
        e_blinding: Scalar::zero(),
        ipp_proof: create_mock_inner_product_proof(),
    }
}

/// Create a mock `InnerProductProof`
fn create_mock_inner_product_proof() -> InnerProductProof {
    InnerProductProof { L_vec: vec![], R_vec: vec![], a: Scalar::zero(), b: Scalar::zero() }
}

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
            ProofJob::ValidMatchMpcSingleprover { witness } => {
                ProofBundle::ValidMatchMpc(Self::valid_match_mpc(witness))
            },
            ProofJob::ValidSettle { witness, statement } => {
                ProofBundle::ValidSettle(Self::valid_settle(witness, statement))
            },
        };

        response_channel.send(bundle).expect(ERR_RESPONSE_CHANNEL_CLOSED);
    }

    /// Generate a dummy proof of `VALID WALLET CREATE`
    fn valid_wallet_create(
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> ValidWalletCreateBundle {
        let commitment = create_mock_commitment::<SizedValidWalletCreate>(witness);
        let proof = create_mock_proof();

        Box::new(GenericValidWalletCreateBundle { statement, commitment, proof })
    }

    /// Generate a dummy proof of `VALID WALLET UPDATE`
    fn valid_wallet_update(
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> ValidWalletUpdateBundle {
        let commitment = create_mock_commitment::<SizedValidWalletUpdate>(witness);
        let proof = create_mock_proof();

        Box::new(GenericValidWalletUpdateBundle { statement, commitment, proof })
    }

    /// Generate a dummy proof of `VALID REBLIND`
    fn valid_reblind(
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> ValidReblindBundle {
        let commitment = create_mock_commitment::<SizedValidReblind>(witness);
        let proof = create_mock_proof();

        Box::new(GenericValidReblindBundle { statement, commitment, proof })
    }

    /// Create a dummy proof of `VALID COMMITMENTS`
    fn valid_commitments(
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> ValidCommitmentsBundle {
        let commitment = create_mock_commitment::<SizedValidCommitments>(witness);
        let proof = create_mock_proof();

        Box::new(GenericValidCommitmentsBundle { statement, commitment, proof })
    }

    /// Create a dummy proof of `VALID MATCH MPC`
    fn valid_match_mpc(witness: ValidMatchMpcWitness) -> ValidMatchMpcBundle {
        let commitment = create_mock_commitment::<ValidMatchMpcSingleProver>(witness);
        let proof = create_mock_proof();

        Box::new(GenericValidMatchMpcBundle { commitment, statement: (), proof })
    }

    /// Create a dummy proof of `VALID SETTLE`
    fn valid_settle(
        witness: SizedValidSettleWitness,
        statement: SizedValidSettleStatement,
    ) -> ValidSettleBundle {
        let commitment = create_mock_commitment::<SizedValidSettle>(witness);
        let proof = create_mock_proof();

        Box::new(GenericValidSettleBundle { statement, commitment, proof })
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use circuit_types::{traits::BaseType, wallet::WalletShare};
    use circuits::zk_circuits::valid_wallet_create::{
        SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    };
    use crossbeam::channel::unbounded;
    use job_types::proof_manager::{ProofJob, ProofManagerJob};
    use mpc_stark::algebra::scalar::Scalar;
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
