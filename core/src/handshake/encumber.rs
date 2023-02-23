//! Implements the handshake manager flow of encumbering a pair of wallets
//! after a match has completed. This involves:
//!     1. Creating notes for the wallets, relayers, and protocol
//!     2. Proving `VALID MATCH ENCRYPTION`
//!     3. Submitting the proofs and data to the contract

use std::convert::TryInto;

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
    zk_gadgets::{
        elgamal::{ElGamalCiphertext, DEFAULT_ELGAMAL_GENERATOR},
        fixed_point::FixedPoint,
    },
};

use crypto::fields::{biguint_to_scalar, prime_field_to_scalar, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::mpc_network::field::get_ristretto_group_modulus;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use num_bigint::BigUint;
use rand_core::OsRng;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    proof_generation::jobs::{ProofJob, ProofManagerJob},
    PROTOCOL_FEE, PROTOCOL_SETTLE_KEY,
};

use super::{error::HandshakeManagerError, manager::HandshakeExecutor, r#match::HandshakeResult};

impl HandshakeExecutor {
    /// Entrypoint to the encumbering flow, creates notes, proves `VALID MATCH ENCRYPTION`,
    /// and submits the match bundle to the contract
    pub(super) fn submit_match(
        &self,
        handshake_result: HandshakeResult,
    ) -> Result<(), HandshakeManagerError> {
        // Create notes for all parties from the match
        #[allow(unused)]
        let (party0_note, party1_note, relayer0_note, relayer1_note, protocol_note) = self
            .create_notes(
                &handshake_result.match_,
                &handshake_result.party0_fee,
                &handshake_result.party1_fee,
                handshake_result.party0_randomness_hash,
                handshake_result.party1_randomness_hash,
            );

        // Create encryptions of all note fields that are not known ahead of time
        let mut randomness_values = Vec::new();

        // Encrypt the volumes of the first party's note under their key
        let pk_settle0_bigint = scalar_to_biguint(&handshake_result.pk_settle0);
        let (volume1_ciphertext1, randomness) =
            Self::encrypt_scalar(party0_note.volume1.into(), &pk_settle0_bigint);
        randomness_values.push(randomness);

        let (volume2_ciphertext1, randomness) =
            Self::encrypt_scalar(party0_note.volume2.into(), &pk_settle0_bigint);
        randomness_values.push(randomness);

        // Encrypt the volumes of the second party's note under their key
        let pk_settle1_bigint = scalar_to_biguint(&handshake_result.pk_settle1);
        let (volume1_ciphertext2, randomness) =
            Self::encrypt_scalar(party1_note.volume1.into(), &pk_settle1_bigint);
        randomness_values.push(randomness);

        let (volume2_ciphertext2, randomness) =
            Self::encrypt_scalar(party1_note.volume2.into(), &pk_settle1_bigint);
        randomness_values.push(randomness);

        // Encrypt the mints, volumes and randomness of the protocol note under the protocol key
        let (mint1_protocol_ciphertext, randomness) = Self::encrypt_scalar(
            biguint_to_scalar(&protocol_note.mint1),
            &PROTOCOL_SETTLE_KEY,
        );
        randomness_values.push(randomness);

        let (mint2_protocol_ciphertext, randomness) = Self::encrypt_scalar(
            biguint_to_scalar(&protocol_note.mint2),
            &PROTOCOL_SETTLE_KEY,
        );
        randomness_values.push(randomness);

        let (volume1_protocol_ciphertext, randomness) =
            Self::encrypt_scalar(protocol_note.volume1.into(), &PROTOCOL_SETTLE_KEY);
        randomness_values.push(randomness);

        let (volume2_protocol_ciphertext, randomness) =
            Self::encrypt_scalar(protocol_note.volume2.into(), &PROTOCOL_SETTLE_KEY);
        randomness_values.push(randomness);

        let (randomness_protocol_ciphertext, encryption_randomness) = Self::encrypt_scalar(
            biguint_to_scalar(&protocol_note.randomness),
            &PROTOCOL_SETTLE_KEY,
        );
        randomness_values.push(encryption_randomness);

        // Construct a statement and witness for `VALID MATCH ENCRYPTION`
        #[allow(unused_variables)]
        let witness = ValidMatchEncryptionWitness {
            match_res: handshake_result.match_,
            party0_fee: handshake_result.party0_fee,
            party1_fee: handshake_result.party1_fee,
            party0_randomness_hash: handshake_result.party0_randomness_hash.into(),
            party1_randomness_hash: handshake_result.party1_randomness_hash.into(),
            party0_note: party0_note.clone(),
            party1_note: party1_note.clone(),
            relayer0_note: relayer0_note.clone(),
            relayer1_note: relayer1_note.clone(),
            protocol_note: protocol_note.clone(),
            elgamal_randomness: randomness_values.try_into().unwrap(),
        };

        #[allow(unused_variables)]
        let statement = ValidMatchEncryptionStatement {
            party0_note_commit: Self::note_commit(&party0_note, handshake_result.pk_settle0),
            party1_note_commit: Self::note_commit(&party1_note, handshake_result.pk_settle1),
            relayer0_note_commit: Self::note_commit(
                &relayer0_note,
                handshake_result.pk_settle_cluster0,
            ),
            relayer1_note_commit: Self::note_commit(
                &relayer1_note,
                handshake_result.pk_settle_cluster1,
            ),
            protocol_note_commit: Self::note_commit(
                &protocol_note,
                biguint_to_scalar(&PROTOCOL_SETTLE_KEY),
            ),
            pk_settle_party0: handshake_result.pk_settle0,
            pk_settle_party1: handshake_result.pk_settle1,
            pk_settle_relayer0: handshake_result.pk_settle_cluster0,
            pk_settle_relayer1: handshake_result.pk_settle_cluster1,
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

        self.prove_valid_encryption(witness, statement)?;

        Ok(())
    }

    /// Generate a proof of `VALID MATCH ENCRYPTION` by forwarding a request to the proof manager
    /// and then awaiting the response
    ///
    /// This code path is executed relatively infrequently (only when a valid match is found), so it
    /// is likely okay to directly block a thread in the pool. If this becomes an issue we can go async
    fn prove_valid_encryption(
        &self,
        witness: ValidMatchEncryptionWitness,
        statement: ValidMatchEncryptionStatement,
    ) -> Result<(), HandshakeManagerError> {
        // Forward the job to the proof manager
        let (response_channel_sender, response_channel_receiver) = oneshot::channel();
        self.proof_manager_work_queue
            .send(ProofManagerJob {
                type_: ProofJob::ValidMatchEncrypt { witness, statement },
                response_channel: response_channel_sender,
            })
            .map_err(|err| HandshakeManagerError::SendMessage(err.to_string()))?;

        // Await the proof manager's response
        let _proof = response_channel_receiver
            .blocking_recv()
            .map_err(|err| HandshakeManagerError::ReceiveProof(err.to_string()))?;

        log::info!("finished proving VALID MATCH ENCRYPTION, encumbering");
        Ok(())
    }

    /// A wrapper around the `circuits` crate's note commitment helper that handles type conversion
    fn note_commit(note: &Note, receiver_key: Scalar) -> Scalar {
        let commitment = compute_note_commitment(note, receiver_key);
        prime_field_to_scalar(&commitment)
    }

    /// Create notes from a match result
    ///
    /// There are 5 notes in total:
    ///     - Each of the parties receives a note for their side of the match (2)
    ///     - Each of the managing relayers receives a note for their fees (2)
    ///     - The protocol receives a note for its fee (1)
    fn create_notes(
        &self,
        match_res: &LinkableMatchResultCommitment,
        party0_fee: &LinkableFeeCommitment,
        party1_fee: &LinkableFeeCommitment,
        party0_randomness_hash: Scalar,
        party1_randomness_hash: Scalar,
    ) -> (Note, Note, Note, Note, Note) {
        // The match direction corresponds to the direction that party 0 goes in the match
        // i.e. the match direction is 0 (buy) if party 0 is buying the base and selling the quote
        let match_direction: OrderSide = match_res.direction.val.into();
        let base_amount_scalar = Scalar::from(match_res.base_amount);
        let quote_amount_scalar = Scalar::from(match_res.quote_amount);

        // Apply fees to the match
        let percent_fee0: FixedPoint = party0_fee.percentage_fee.into();
        let percent_fee1: FixedPoint = party1_fee.percentage_fee.into();
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
                        scalar_to_u64(&match_res.quote_amount.into()),
                        scalar_to_u64(&match_res.base_amount.into()),
                        party1_quote,
                    )
                }
                OrderSide::Sell => {
                    let party0_quote =
                        scalar_to_u64(&(party0_net_percentage * quote_amount_scalar).floor());
                    let party1_base =
                        scalar_to_u64(&(party1_net_percentage * base_amount_scalar).floor());

                    (
                        scalar_to_u64(&match_res.base_amount.into()),
                        party0_quote,
                        party1_base,
                        scalar_to_u64(&match_res.quote_amount.into()),
                    )
                }
            };

        let party0_note = Note {
            mint1: scalar_to_biguint(&match_res.base_mint.into()),
            volume1: party0_base_amount,
            direction1: match_direction,
            mint2: scalar_to_biguint(&match_res.quote_mint.into()),
            volume2: party0_quote_amount,
            direction2: match_direction.opposite(),
            fee_mint: scalar_to_biguint(&party0_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&party0_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: scalar_to_biguint(&party0_randomness_hash),
        };

        let party1_note = Note {
            mint1: scalar_to_biguint(&match_res.base_mint.into()),
            volume1: party1_base_amount,
            direction1: match_direction.opposite(),
            mint2: scalar_to_biguint(&match_res.quote_mint.into()),
            volume2: party1_quote_amount,
            direction2: match_direction,
            fee_mint: scalar_to_biguint(&party1_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&party1_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: scalar_to_biguint(&party1_randomness_hash),
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
            mint1: scalar_to_biguint(&match_res.base_mint.into()),
            volume1: relayer0_base_amount,
            direction1: OrderSide::Buy,
            mint2: scalar_to_biguint(&match_res.quote_mint.into()),
            volume2: relayer0_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: scalar_to_biguint(&party0_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&party0_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: scalar_to_biguint(&(party0_randomness_hash + Scalar::one())),
        };

        let relayer1_note = Note {
            mint1: scalar_to_biguint(&match_res.base_mint.into()),
            volume1: relayer1_base_amount,
            direction1: OrderSide::Buy,
            mint2: scalar_to_biguint(&match_res.quote_mint.into()),
            volume2: relayer1_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: scalar_to_biguint(&party1_fee.gas_addr.into()),
            fee_volume: scalar_to_u64(&party1_fee.gas_token_amount.into()),
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: scalar_to_biguint(&(party1_randomness_hash + Scalar::one())),
        };

        // Build the protocol note
        let protocol_base_amount = scalar_to_u64(&(*PROTOCOL_FEE * base_amount_scalar).floor());
        let protocol_quote_amount = scalar_to_u64(&(*PROTOCOL_FEE * quote_amount_scalar).floor());

        let protocol_note = Note {
            mint1: scalar_to_biguint(&match_res.base_mint.into()),
            volume1: protocol_base_amount,
            direction1: OrderSide::Buy,
            mint2: scalar_to_biguint(&match_res.quote_mint.into()),
            volume2: protocol_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: 0u8.into(),
            fee_volume: 0,
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: scalar_to_biguint(&(party0_randomness_hash + party1_randomness_hash)),
        };

        (
            party0_note,
            party1_note,
            relayer0_note,
            relayer1_note,
            protocol_note,
        )
    }

    /// Create an ElGamal encryption of the given value
    ///
    /// Return both the encryption (used as a public variable) and the randomness
    /// used to generate the encryption (used as a witness variable)
    fn encrypt_scalar(val: Scalar, pubkey: &BigUint) -> (ElGamalCiphertext, Scalar) {
        let mut rng = OsRng {};
        let randomness = scalar_to_biguint(&Scalar::random(&mut rng));

        let field_mod = get_ristretto_group_modulus();
        let ciphertext1 =
            scalar_to_biguint(&DEFAULT_ELGAMAL_GENERATOR).modpow(&randomness, &field_mod);
        let shared_secret = pubkey.modpow(&randomness, &field_mod);

        let encrypted_message = (shared_secret * scalar_to_biguint(&val)) % &field_mod;

        (
            ElGamalCiphertext {
                partial_shared_secret: biguint_to_scalar(&ciphertext1),
                encrypted_message: biguint_to_scalar(&encrypted_message),
            },
            biguint_to_scalar(&randomness),
        )
    }
}
