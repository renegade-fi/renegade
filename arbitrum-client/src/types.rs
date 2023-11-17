//! Analogous definitions of types from the smart contracts for use in the
//! relayer

// TODO: Replace statement types from the smart contracts with relayer statement
// types once they're adapted to Plonk

use constants::Scalar;
use renegade_contracts_common::types::{ValidCommitmentsStatement, ValidReblindStatement};

/// The aggregated statements produced by a single party in a match
pub struct MatchPayload {
    /// The public secret share of the party's wallet-level blinder
    pub wallet_blinder_share: Scalar,
    /// The party's `VALID COMMITMENTS` statement
    pub valid_commitments_statement: ValidCommitmentsStatement,
    /// The party's `VALID REBLIND` statement
    pub valid_reblind_statement: ValidReblindStatement,
}
