//! Implements the handshake manager flow of encumbering a pair of wallets
//! after a match has completed. This involves:
//!     1. Creating notes for the wallets, relayers, and protocol
//!     2. Proving `VALID MATCH ENCRYPTION`
//!     3. Submitting the proofs and data to the contract

use circuits::types::{
    fee::Fee,
    note::{Note, NoteType},
    order::OrderSide,
    r#match::MatchResult,
};
use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::mpc_scalar::scalar_to_u64;

use crate::PROTOCOL_FEE;

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
            );

        Ok(())
    }

    /// Create notes from a match result
    ///
    /// There are 5 notes in total:
    ///     - Each of the parties receives a note for their side of the match (2)
    ///     - Each of the managing relayers receives a note for their fees (2)
    ///     - The protocol receives a note for its fee (1)
    fn create_notes(
        &self,
        match_res: &MatchResult,
        party0_fee: &Fee,
        party1_fee: &Fee,
    ) -> (Note, Note, Note, Note, Note) {
        // The match direction corresponds to the direction that party 0 goes in the match
        // i.e. the match direction is 0 (buy) if party 0 is buying the base and selling the quote
        let match_direction: OrderSide = match_res.direction.into();
        let base_amount_scalar = Scalar::from(match_res.base_amount);
        let quote_amount_scalar = Scalar::from(match_res.quote_amount);

        // Apply fees to the match
        let party0_net_percentage = Scalar::one() - party0_fee.percentage_fee - *PROTOCOL_FEE;
        let party1_net_percentage = Scalar::one() - party1_fee.percentage_fee - *PROTOCOL_FEE;

        let (party0_base_amount, party0_quote_amount, party1_base_amount, party1_quote_amount) =
            match match_direction {
                OrderSide::Buy => {
                    let party0_base =
                        scalar_to_u64(&(party0_net_percentage * base_amount_scalar).floor());
                    let party1_quote =
                        scalar_to_u64(&(party1_net_percentage * quote_amount_scalar).floor());

                    (
                        party0_base,
                        match_res.quote_amount,
                        match_res.base_amount,
                        party1_quote,
                    )
                }
                OrderSide::Sell => {
                    let party0_quote =
                        scalar_to_u64(&(party0_net_percentage * quote_amount_scalar).floor());
                    let party1_base =
                        scalar_to_u64(&(party1_net_percentage * base_amount_scalar).floor());

                    (
                        match_res.base_amount,
                        party0_quote,
                        party1_base,
                        match_res.quote_amount,
                    )
                }
            };

        // TODO: Fix randomness
        let party0_note = Note {
            mint1: match_res.base_mint.clone(),
            volume1: party0_base_amount,
            direction1: match_direction,
            mint2: match_res.quote_mint.clone(),
            volume2: party0_quote_amount,
            direction2: match_direction.opposite(),
            fee_mint: party0_fee.gas_addr.clone(),
            fee_volume: party0_fee.gas_token_amount,
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: 0,
        };

        let party1_note = Note {
            mint1: match_res.base_mint.clone(),
            volume1: party1_base_amount,
            direction1: match_direction.opposite(),
            mint2: match_res.quote_mint.clone(),
            volume2: party1_quote_amount,
            direction2: match_direction,
            fee_mint: party1_fee.gas_addr.clone(),
            fee_volume: party1_fee.gas_token_amount,
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: 0,
        };

        // Create the relayer notes
        let (
            relayer0_base_amount,
            relayer0_quote_amount,
            relayer1_base_amount,
            relayer1_quote_amount,
        ) = match match_direction {
            OrderSide::Buy => {
                let relayer0_base =
                    scalar_to_u64(&(party0_fee.percentage_fee * base_amount_scalar).floor());
                let relayer1_quote =
                    scalar_to_u64(&(party1_fee.percentage_fee * quote_amount_scalar).floor());

                (relayer0_base, 0, 0, relayer1_quote)
            }
            OrderSide::Sell => {
                let relayer0_quote =
                    scalar_to_u64(&(party0_fee.percentage_fee * quote_amount_scalar).floor());
                let relayer1_base =
                    scalar_to_u64(&(party1_fee.percentage_fee * base_amount_scalar).floor());

                (0, relayer0_quote, relayer1_base, 0)
            }
        };

        let relayer0_note = Note {
            mint1: match_res.base_mint.clone(),
            volume1: relayer0_base_amount,
            direction1: OrderSide::Buy,
            mint2: match_res.quote_mint.clone(),
            volume2: relayer0_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: party0_fee.gas_addr.clone(),
            fee_volume: party0_fee.gas_token_amount,
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: 0,
        };

        let relayer1_note = Note {
            mint1: match_res.base_mint.clone(),
            volume1: relayer1_base_amount,
            direction1: OrderSide::Buy,
            mint2: match_res.quote_mint.clone(),
            volume2: relayer1_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: party1_fee.gas_addr.clone(),
            fee_volume: party1_fee.gas_token_amount,
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: 0,
        };

        // Build the protocol note
        let protocol_base_amount = scalar_to_u64(&(*PROTOCOL_FEE * base_amount_scalar).floor());
        let protocol_quote_amount = scalar_to_u64(&(*PROTOCOL_FEE * quote_amount_scalar).floor());

        let protocol_note = Note {
            mint1: match_res.base_mint.clone(),
            volume1: protocol_base_amount,
            direction1: OrderSide::Buy,
            mint2: match_res.quote_mint.clone(),
            volume2: protocol_quote_amount,
            direction2: OrderSide::Buy,
            fee_mint: 0u8.into(),
            fee_volume: 0,
            fee_direction: OrderSide::Buy,
            type_: NoteType::InternalTransfer,
            randomness: 0,
        };

        (
            party0_note,
            party1_note,
            relayer0_note,
            relayer1_note,
            protocol_note,
        )
    }
}
