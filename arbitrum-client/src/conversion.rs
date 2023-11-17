//! Utilities for converting from relayer type definitions to their analogues in
//! ther smart contracts.

use constants::{SystemCommitment, SystemProof};
use renegade_contracts_common::types::{
    G1Affine, MatchPayload as ContractMatchPayload, Proof as ContractProof,
};

use crate::{errors::ConversionError, types::MatchPayload};

/// Try to extract a fixed-length array of G1Affine points
/// from a slice of proof system commitments
fn try_unwrap_commitments<const N: usize>(
    comms: &[SystemCommitment],
) -> Result<[G1Affine; N], ConversionError> {
    comms
        .iter()
        .map(|c| c.0)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}

/// Trait for converting from relayer types to their smart contract analogues
pub trait ToContractType<T> {
    /// Convert the type to its smart contract analogue
    fn to_contract_type(self) -> Result<T, ConversionError>;
}

impl ToContractType<ContractProof> for SystemProof {
    fn to_contract_type(self) -> Result<ContractProof, ConversionError> {
        Ok(ContractProof {
            wire_comms: try_unwrap_commitments(&self.wires_poly_comms)?,
            z_comm: self.prod_perm_poly_comm.0,
            quotient_comms: try_unwrap_commitments(&self.split_quot_poly_comms)?,
            w_zeta: self.opening_proof.0,
            w_zeta_omega: self.shifted_opening_proof.0,
            wire_evals: self
                .poly_evals
                .wires_evals
                .try_into()
                .map_err(|_| ConversionError::InvalidLength)?,
            sigma_evals: self
                .poly_evals
                .wire_sigma_evals
                .try_into()
                .map_err(|_| ConversionError::InvalidLength)?,
            z_bar: self.poly_evals.perm_next_eval,
        })
    }
}

impl ToContractType<ContractMatchPayload> for MatchPayload {
    fn to_contract_type(self) -> Result<ContractMatchPayload, ConversionError> {
        Ok(ContractMatchPayload {
            wallet_blinder_share: self.wallet_blinder_share.inner(),
            valid_commitments_statement: self.valid_commitments_statement,
            valid_reblind_statement: self.valid_reblind_statement,
        })
    }
}
