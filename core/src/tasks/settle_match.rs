//! Groups the task definition for settling a match after an MPC has taken place
//! Broadly this breaks down into the following steps:
//!     - Build the notes that result from the match and encrypt them
//!     - Submit these notes and the relevant proofs to the contract in a `match` transaction
//!     - Await transaction finality, then lookup the notes in the commitment tree
//!     - Build a settlement proof, and submit this to the contract in a `settle` transaction
//!     - Await finality then update the wallets into the relayer-global state

// TODO: Remove this
#![allow(unused)]

use std::{
    convert::TryInto,
    fmt::{Display, Formatter, Result as FmtResult},
};

use async_trait::async_trait;
use circuits::{
    native_helpers::compute_note_commitment,
    types::{
        fee::LinkableFeeCommitment,
        note::{Note, NoteType},
        order::OrderSide,
        r#match::LinkableMatchResultCommitment,
    },
    zk_circuits::valid_match_encryption::{
        ValidMatchEncryptionStatement, ValidMatchEncryptionWitness,
    },
    zk_gadgets::fixed_point::FixedPoint,
    LinkableCommitment,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::{
    elgamal::encrypt_scalar,
    fields::{biguint_to_scalar, prime_field_to_scalar, scalar_to_biguint},
};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use serde::Serialize;
use tokio::sync::oneshot;

use crate::{
    handshake::r#match::HandshakeResult,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidMatchEncryptBundle},
    starknet_client::client::StarknetClient,
    state::RelayerState,
    PROTOCOL_FEE, PROTOCOL_SETTLE_KEY,
};

use super::driver::{StateWrapper, Task};

/// The displayable name for the settle match task
const SETTLE_MATCH_TASK_NAME: &str = "settle-match";

// -----------
// | Helpers |
// -----------

/// A wrapper around the `circuits` crate's note commitment helper that handles type conversion
fn note_commit(note: &Note, receiver_key: Scalar) -> Scalar {
    let commitment = compute_note_commitment(note, receiver_key);
    prime_field_to_scalar(&commitment)
}

// -------------------
// | Task Definition |
// -------------------

/// Describes the settle task
pub struct SettleMatchTask {
    /// The result of the match process
    pub handshake_result: HandshakeResult,
    /// The starknet client to use for submitting transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task
    pub task_state: SettleMatchTaskState,
}

/// The state of the settle match task
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum SettleMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving `VALID MATCH ENCRYPTION`
    ProvingEncryption,
    /// The task is submitting the match transaction
    SubmittingMatch {
        /// The proof of `VALID MATCH ENCRYPTION`
        proof: ValidMatchEncryptBundle,
    },
    /// The task is proving `VALID SETTLE`
    ProvingSettle,
    /// The task is submitting the settle transaction
    SubmittingSettle {
        /// The proof of `VALID SETTLE`
        proof: (),
    },
    /// The task is updating order proofs after the settled walled is confirmed
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl From<SettleMatchTaskState> for StateWrapper {
    fn from(state: SettleMatchTaskState) -> Self {
        StateWrapper::SettleMatch(state)
    }
}

/// Display implementation that removes variant fields
impl Display for SettleMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettleMatchTaskState::SubmittingMatch { .. } => write!(f, "SubmittingMatch"),
            SettleMatchTaskState::SubmittingSettle { .. } => write!(f, "SubmittingSettle"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// The error type that this task emits
#[derive(Clone, Debug, Serialize)]
pub enum SettleMatchTaskError {
    /// Error generating a proof
    ProofGeneration(String),
    /// Error sending a message to another local worker
    SendMessage(String),
}

impl Display for SettleMatchTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

#[async_trait]
impl Task for SettleMatchTask {
    type State = SettleMatchTaskState;
    type Error = SettleMatchTaskError;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current task state
        match self.state() {
            SettleMatchTaskState::Pending => {
                self.task_state = SettleMatchTaskState::ProvingEncryption
            }

            SettleMatchTaskState::ProvingEncryption => {
                let proof = self.prove_encryption().await?;
                self.task_state = SettleMatchTaskState::SubmittingMatch { proof };
            }

            SettleMatchTaskState::SubmittingMatch { proof } => {
                self.submit_match(proof)?;
                self.task_state = SettleMatchTaskState::ProvingSettle;
            }

            SettleMatchTaskState::ProvingSettle => {
                let proof = self.prove_settle()?;
                self.task_state = SettleMatchTaskState::SubmittingSettle { proof };
            }

            SettleMatchTaskState::SubmittingSettle { proof } => {
                self.submit_settle(proof)?;
                self.task_state = SettleMatchTaskState::UpdatingValidityProofs;
            }

            SettleMatchTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs()?;
                self.task_state = SettleMatchTaskState::Completed;
            }

            SettleMatchTaskState::Completed => {
                unreachable!("step called on completed task")
            }
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_MATCH_TASK_NAME.to_string()
    }

    fn completed(&self) -> bool {
        matches!(self.state(), SettleMatchTaskState::Completed)
    }

    fn state(&self) -> SettleMatchTaskState {
        self.task_state.clone()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettleMatchTask {
    /// Constructor
    pub fn new(
        handshake_result: HandshakeResult,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            handshake_result,
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_state: SettleMatchTaskState::Pending,
        }
    }

    /// Prove `VALID MATCH ENCRYPTION` on the match
    async fn prove_encryption(&self) -> Result<ValidMatchEncryptBundle, SettleMatchTaskError> {
        // Construct the witness and statement
        let (statement, witness) = self.build_encrypt_statement_witness()?;

        // Enqueue a job with the proof manager and await a response
        let (response_sender, response_receiver) = oneshot::channel();
        self.proof_manager_work_queue
            .send(ProofManagerJob {
                type_: ProofJob::ValidMatchEncrypt { witness, statement },
                response_channel: response_sender,
            })
            .map_err(|err| SettleMatchTaskError::SendMessage(err.to_string()))?;

        response_receiver
            .await
            .map(|bundle| bundle.into())
            .map_err(|err| SettleMatchTaskError::ProofGeneration(err.to_string()))
    }

    /// Build a witness and statement to `VALID MATCH ENCRYPT`
    fn build_encrypt_statement_witness(
        &self,
    ) -> Result<(ValidMatchEncryptionStatement, ValidMatchEncryptionWitness), SettleMatchTaskError>
    {
        // Create notes for the match
        let (party0_note, party1_note, relayer0_note, relayer1_note, protocol_note) =
            self.create_notes();

        // Create encryptions of all note fields not known ahead of time
        let mut randomness_values = Vec::new();

        // Encrypt the volumes of the first party's note under their key
        let pk_settle0_bigint = scalar_to_biguint(&self.handshake_result.pk_settle0);
        let (volume1_ciphertext1, randomness) =
            encrypt_scalar(party0_note.volume1.into(), &pk_settle0_bigint);
        randomness_values.push(randomness);

        let (volume2_ciphertext1, randomness) =
            encrypt_scalar(party0_note.volume2.into(), &pk_settle0_bigint);
        randomness_values.push(randomness);

        // Encrypt the volumes of the second party's note under their key
        let pk_settle1_bigint = scalar_to_biguint(&self.handshake_result.pk_settle1);
        let (volume1_ciphertext2, randomness) =
            encrypt_scalar(party1_note.volume1.into(), &pk_settle1_bigint);
        randomness_values.push(randomness);

        let (volume2_ciphertext2, randomness) =
            encrypt_scalar(party1_note.volume2.into(), &pk_settle1_bigint);
        randomness_values.push(randomness);

        // Encrypt the mints, volumes and randomness of the protocol note under the protocol key
        let (mint1_protocol_ciphertext, randomness) = encrypt_scalar(
            biguint_to_scalar(&protocol_note.mint1),
            &PROTOCOL_SETTLE_KEY,
        );
        randomness_values.push(randomness);

        let (mint2_protocol_ciphertext, randomness) = encrypt_scalar(
            biguint_to_scalar(&protocol_note.mint2),
            &PROTOCOL_SETTLE_KEY,
        );
        randomness_values.push(randomness);

        let (volume1_protocol_ciphertext, randomness) =
            encrypt_scalar(protocol_note.volume1.into(), &PROTOCOL_SETTLE_KEY);
        randomness_values.push(randomness);

        let (volume2_protocol_ciphertext, randomness) =
            encrypt_scalar(protocol_note.volume2.into(), &PROTOCOL_SETTLE_KEY);
        randomness_values.push(randomness);

        let (randomness_protocol_ciphertext, encryption_randomness) = encrypt_scalar(
            biguint_to_scalar(&protocol_note.randomness),
            &PROTOCOL_SETTLE_KEY,
        );
        randomness_values.push(encryption_randomness);

        // Construct a statement and witness for `VALID MATCH ENCRYPTION`
        let witness = ValidMatchEncryptionWitness {
            match_res: self.handshake_result.match_.clone(),
            party0_fee: self.handshake_result.party0_fee.clone(),
            party1_fee: self.handshake_result.party1_fee.clone(),
            party0_randomness_hash: self.handshake_result.party0_randomness_hash,
            party1_randomness_hash: self.handshake_result.party1_randomness_hash,
            party0_note: party0_note.clone(),
            party1_note: party1_note.clone(),
            relayer0_note: relayer0_note.clone(),
            relayer1_note: relayer1_note.clone(),
            protocol_note: protocol_note.clone(),
            elgamal_randomness: randomness_values.try_into().unwrap(),
        };

        let statement = ValidMatchEncryptionStatement {
            party0_note_commit: note_commit(&party0_note, self.handshake_result.pk_settle0),
            party1_note_commit: note_commit(&party1_note, self.handshake_result.pk_settle1),
            relayer0_note_commit: note_commit(
                &relayer0_note,
                self.handshake_result.pk_settle_cluster0,
            ),
            relayer1_note_commit: note_commit(
                &relayer1_note,
                self.handshake_result.pk_settle_cluster1,
            ),
            protocol_note_commit: note_commit(
                &protocol_note,
                biguint_to_scalar(&PROTOCOL_SETTLE_KEY),
            ),
            pk_settle_party0: self.handshake_result.pk_settle0,
            pk_settle_party1: self.handshake_result.pk_settle1,
            pk_settle_relayer0: self.handshake_result.pk_settle_cluster0,
            pk_settle_relayer1: self.handshake_result.pk_settle_cluster1,
            pk_settle_protocol: biguint_to_scalar(&PROTOCOL_SETTLE_KEY),
            protocol_fee: *PROTOCOL_FEE,
            volume1_ciphertext1,
            volume2_ciphertext1,
            volume1_ciphertext2,
            volume2_ciphertext2,
            mint1_protocol_ciphertext,
            volume1_protocol_ciphertext,
            mint2_protocol_ciphertext,
            volume2_protocol_ciphertext,
            randomness_protocol_ciphertext,
        };

        Ok((statement, witness))
    }

    /// Create notes from a match result
    ///
    /// There are 5 notes in total:
    ///     - Each of the parties receives a note for their side of the match (2)
    ///     - Each of the managing relayers receives a note for their fees (2)
    ///     - The protocol receives a note for its fee (1)
    fn create_notes(&self) -> (Note, Note, Note, Note, Note) {
        // The match direction corresponds to the direction that party 0 goes in the match
        // i.e. the match direction is 0 (buy) if party 0 is buying the base and selling the quote
        let match_direction: OrderSide = self.handshake_result.match_.direction.val.into();
        let base_amount_scalar = Scalar::from(self.handshake_result.match_.base_amount);
        let quote_amount_scalar = Scalar::from(self.handshake_result.match_.quote_amount);
        let randomness_hash0_scalar = Scalar::from(self.handshake_result.party0_randomness_hash);
        let randomness_hash1_scalar = Scalar::from(self.handshake_result.party1_randomness_hash);

        // Apply fees to the match
        let percent_fee0: FixedPoint = self.handshake_result.party0_fee.percentage_fee.into();
        let percent_fee1: FixedPoint = self.handshake_result.party1_fee.percentage_fee.into();
        let party0_net_percentage = Scalar::one() - percent_fee0 - *PROTOCOL_FEE;
        let party1_net_percentage = Scalar::one() - percent_fee1 - *PROTOCOL_FEE;

        let (party0_base_amount, party0_quote_amount, party1_base_amount, party1_quote_amount) =
            match match_direction {
                OrderSide::Buy => {
                    let party0_base =
                        scalar_to_u64(&(party0_net_percentage * base_amount_scalar).floor());
                    let party1_quote =
                        scalar_to_u64(&(party1_net_percentage * quote_amount_scalar).floor());

                    (
                        party0_base,
                        scalar_to_u64(&self.handshake_result.match_.quote_amount.into()),
                        scalar_to_u64(&self.handshake_result.match_.base_amount.into()),
                        party1_quote,
                    )
                }
                OrderSide::Sell => {
                    let party0_quote =
                        scalar_to_u64(&(party0_net_percentage * quote_amount_scalar).floor());
                    let party1_base =
                        scalar_to_u64(&(party1_net_percentage * base_amount_scalar).floor());

                    (
                        scalar_to_u64(&self.handshake_result.match_.base_amount.into()),
                        party0_quote,
                        party1_base,
                        scalar_to_u64(&self.handshake_result.match_.quote_amount.into()),
                    )
                }
            };

        let party0_note = Note {
            mint1: scalar_to_biguint(&self.handshake_result.match_.base_mint.into()),
            volume1: party0_base_amount,
            direction1: match_direction,
            mint2: scalar_to_biguint(&self.handshake_result.match_.quote_mint.into()),
            volume2: party0_quote_amount,
            direction2: match_direction.opposite(),
            fee_mint: scalar_to_biguint(&self.handshake_result.party0_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&self.handshake_result.party0_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: scalar_to_biguint(&randomness_hash0_scalar),
        };

        let party1_note = Note {
            mint1: scalar_to_biguint(&self.handshake_result.match_.base_mint.into()),
            volume1: party1_base_amount,
            direction1: match_direction.opposite(),
            mint2: scalar_to_biguint(&self.handshake_result.match_.quote_mint.into()),
            volume2: party1_quote_amount,
            direction2: match_direction,
            fee_mint: scalar_to_biguint(&self.handshake_result.party1_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&self.handshake_result.party1_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: scalar_to_biguint(&randomness_hash1_scalar),
        };

        // Create the relayer notes
        let (
            relayer0_base_amount,
            relayer0_quote_amount,
            relayer1_base_amount,
            relayer1_quote_amount,
        ) = match match_direction {
            OrderSide::Buy => {
                let relayer0_base = scalar_to_u64(&(percent_fee0 * base_amount_scalar).floor());
                let relayer1_quote = scalar_to_u64(&(percent_fee1 * quote_amount_scalar).floor());

                (relayer0_base, 0, 0, relayer1_quote)
            }
            OrderSide::Sell => {
                let relayer0_quote = scalar_to_u64(&(percent_fee0 * quote_amount_scalar).floor());
                let relayer1_base = scalar_to_u64(&(percent_fee1 * base_amount_scalar).floor());

                (0, relayer0_quote, relayer1_base, 0)
            }
        };

        let relayer0_note = Note {
            mint1: scalar_to_biguint(&self.handshake_result.match_.base_mint.into()),
            volume1: relayer0_base_amount,
            direction1: OrderSide::Buy,
            mint2: scalar_to_biguint(&self.handshake_result.match_.quote_mint.into()),
            volume2: relayer0_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: scalar_to_biguint(&self.handshake_result.party0_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&self.handshake_result.party0_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: scalar_to_biguint(&(randomness_hash0_scalar + Scalar::one())),
        };

        let relayer1_note = Note {
            mint1: scalar_to_biguint(&self.handshake_result.match_.base_mint.into()),
            volume1: relayer1_base_amount,
            direction1: OrderSide::Buy,
            mint2: scalar_to_biguint(&self.handshake_result.match_.quote_mint.into()),
            volume2: relayer1_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: scalar_to_biguint(&self.handshake_result.party1_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&self.handshake_result.party1_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: scalar_to_biguint(&(randomness_hash1_scalar + Scalar::one())),
        };

        // Build the protocol note
        let protocol_base_amount = scalar_to_u64(&(*PROTOCOL_FEE * base_amount_scalar).floor());
        let protocol_quote_amount = scalar_to_u64(&(*PROTOCOL_FEE * quote_amount_scalar).floor());

        let protocol_note = Note {
            mint1: scalar_to_biguint(&self.handshake_result.match_.base_mint.into()),
            volume1: protocol_base_amount,
            direction1: OrderSide::Buy,
            mint2: scalar_to_biguint(&self.handshake_result.match_.quote_mint.into()),
            volume2: protocol_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: 0u8.into(),
            fee_volume: 0,
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: scalar_to_biguint(&(randomness_hash0_scalar + randomness_hash1_scalar)),
        };

        (
            party0_note,
            party1_note,
            relayer0_note,
            relayer1_note,
            protocol_note,
        )
    }

    /// Submit the match transaction to the contract
    fn submit_match(&self, proof: ValidMatchEncryptBundle) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Prove `VALID SETTLE` on the transaction
    fn prove_settle(&self) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Submit the settle transaction to the contract
    fn submit_settle(&self, proof: ()) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }

    /// Update the validity proofs for all orders in the wallet after settlement
    fn update_validity_proofs(&self) -> Result<(), SettleMatchTaskError> {
        unimplemented!("")
    }
}
