//! Defines native and circuit types for internal/external transfers

// ----------------------
// | External Transfers |
// ----------------------

use crypto::fields::biguint_to_scalar;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::r1cs::{Prover, RandomizableConstraintSystem, Variable, Verifier};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{CommitProver, CommitVerifier};

/// The base external transfer type, not allocated in a constraint system
/// or an MPC circuit
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExternalTransfer {
    /// The address of the account contract to transfer to/from
    pub account_addr: BigUint,
    /// The mint (ERC20 address) of the token to transfer
    pub mint: BigUint,
    /// The amount of the token transferred
    pub amount: BigUint,
    /// The direction of transfer
    pub direction: ExternalTransferDirection,
}

impl ExternalTransfer {
    /// Commit to the external transfer as a public variable
    pub fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> ExternalTransferVar {
        let account_addr_var = cs.commit_public(biguint_to_scalar(&self.account_addr));
        let mint_var = cs.commit_public(biguint_to_scalar(&self.mint));
        let amount_var = cs.commit_public(biguint_to_scalar(&self.amount));
        let dir_var = cs.commit_public(self.direction.into());

        ExternalTransferVar {
            account_addr: account_addr_var,
            mint: mint_var,
            amount: amount_var,
            direction: dir_var,
        }
    }
}

/// Represents the direction (deposit/withdraw) of a transfer
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ExternalTransferDirection {
    /// Deposit an ERC20 into the darkpool from an external address
    Deposit = 0,
    /// Withdraw an ERC20 from the darkpool to an external address
    Withdrawal,
}

impl Default for ExternalTransferDirection {
    fn default() -> Self {
        Self::Deposit
    }
}

impl From<ExternalTransferDirection> for Scalar {
    fn from(dir: ExternalTransferDirection) -> Self {
        Scalar::from(dir as u8)
    }
}

/// Represents an external transfer that has been allocated in a constraint system
#[derive(Copy, Clone, Debug)]
pub struct ExternalTransferVar {
    /// The address of the account contract to transfer to/from
    pub account_addr: Variable,
    /// The mint (ERC20 address) of the token to transfer
    pub mint: Variable,
    /// The amount of the token transferred
    pub amount: Variable,
    /// The direction of transfer
    pub direction: Variable,
}

/// Represents a commitment to a witness variable of type `ExternalTransfer`
#[derive(Copy, Clone, Debug)]
pub struct ExternalTransferCommitment {
    /// The address of the account contract to transfer to/from
    pub account_addr: CompressedRistretto,
    /// The mint (ERC20 address) of the token to transfer
    pub mint: CompressedRistretto,
    /// The amount of the token transferred
    pub amount: CompressedRistretto,
    /// The direction of transfer
    pub direction: CompressedRistretto,
}

impl CommitProver for ExternalTransfer {
    type VarType = ExternalTransferVar;
    type CommitType = ExternalTransferCommitment;
    type ErrorType = (); // Does not error

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        // Commit to the witness vars
        let (account_addr_comm, account_addr_var) =
            prover.commit(biguint_to_scalar(&self.account_addr), Scalar::random(rng));
        let (mint_comm, mint_var) =
            prover.commit(biguint_to_scalar(&self.mint), Scalar::random(rng));
        let (amount_comm, amount_var) =
            prover.commit(biguint_to_scalar(&self.amount), Scalar::random(rng));
        let (direction_comm, direction_var) =
            prover.commit(self.direction.into(), Scalar::random(rng));

        Ok((
            ExternalTransferVar {
                account_addr: account_addr_var,
                mint: mint_var,
                amount: amount_var,
                direction: direction_var,
            },
            ExternalTransferCommitment {
                account_addr: account_addr_comm,
                mint: mint_comm,
                amount: amount_comm,
                direction: direction_comm,
            },
        ))
    }
}

impl CommitVerifier for ExternalTransferCommitment {
    type VarType = ExternalTransferVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let account_addr_var = verifier.commit(self.account_addr);
        let mint_var = verifier.commit(self.mint);
        let amount_var = verifier.commit(self.amount);
        let direction_var = verifier.commit(self.direction);

        Ok(ExternalTransferVar {
            account_addr: account_addr_var,
            mint: mint_var,
            amount: amount_var,
            direction: direction_var,
        })
    }
}

// ---------------------
// | Internal Transfer |
// ---------------------

/// Represents an internal transfer tuple, not allocated in any constraint system
#[derive(Clone, Debug, Default)]
pub struct InternalTransfer {
    /// The mint to transfer
    pub mint: BigUint,
    /// The amount to transfer
    pub amount: BigUint,
}

/// Represents an internal transfer that has been allocated in a constraint system
#[derive(Copy, Clone, Debug)]
pub struct InternalTransferVar {
    /// The mint to transfer
    pub mint: Variable,
    /// The amount to transfer
    pub amount: Variable,
}

/// Represents a commitment to an allocated internal transfer
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct InternalTransferCommitment {
    /// The mint to transfer
    pub mint: CompressedRistretto,
    /// The amount to transfer
    pub amount: CompressedRistretto,
}

impl CommitProver for InternalTransfer {
    type VarType = InternalTransferVar;
    type CommitType = InternalTransferCommitment;
    type ErrorType = (); // Does not error

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (mint_comm, mint_var) =
            prover.commit(biguint_to_scalar(&self.mint), Scalar::random(rng));
        let (amount_comm, amount_var) =
            prover.commit(biguint_to_scalar(&self.amount), Scalar::random(rng));

        Ok((
            InternalTransferVar {
                mint: mint_var,
                amount: amount_var,
            },
            InternalTransferCommitment {
                mint: mint_comm,
                amount: amount_comm,
            },
        ))
    }
}

impl CommitVerifier for InternalTransferCommitment {
    type VarType = InternalTransferVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let mint_var = verifier.commit(self.mint);
        let amount_var = verifier.commit(self.amount);

        Ok(InternalTransferVar {
            mint: mint_var,
            amount: amount_var,
        })
    }
}
