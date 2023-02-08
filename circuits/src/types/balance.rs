//! Groups base and derived types for the `Balance` object

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::{
    r1cs::{Prover, Variable, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{MpcError, TypeConversionError},
    mpc::SharedFabric,
    Allocate, CommitProver, CommitSharedProver, CommitVerifier,
};

/// Represents the base type of a balance in tuple holding a reference to the
/// ERC-20 token and its amount
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// The mint (ERC-20 token address) of the token in the balance
    pub mint: u64,
    /// The amount of the given token stored in this balance
    pub amount: u64,
}

/// Convert a vector of u64s to a Balance
impl TryFrom<&[u64]> for Balance {
    type Error = TypeConversionError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        if values.len() != 2 {
            return Err(TypeConversionError(format!(
                "expected array of length 2, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            mint: values[0],
            amount: values[1],
        })
    }
}

impl From<&Balance> for Vec<u64> {
    fn from(balance: &Balance) -> Self {
        vec![balance.mint, balance.amount]
    }
}

/// Represents the constraint system allocated type of a balance in tuple holding a
/// reference to the ERC-20 token and its amount
#[derive(Copy, Clone, Debug)]
pub struct BalanceVar {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: Variable,
    /// the amount of the given token stored in this balance
    pub amount: Variable,
}

impl From<BalanceVar> for Vec<Variable> {
    fn from(balance: BalanceVar) -> Self {
        vec![balance.mint, balance.amount]
    }
}

impl CommitProver for Balance {
    type VarType = BalanceVar;
    type CommitType = CommittedBalance;
    type ErrorType = (); // Does not error

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (mint_comm, mint_var) = prover.commit(Scalar::from(self.mint), Scalar::random(rng));
        let (amount_comm, amount_var) =
            prover.commit(Scalar::from(self.amount), Scalar::random(rng));

        Ok((
            BalanceVar {
                mint: mint_var,
                amount: amount_var,
            },
            CommittedBalance {
                mint: mint_comm,
                amount: amount_comm,
            },
        ))
    }
}

/// Represents the committed type of the balance tuple
#[derive(Clone, Debug)]
pub struct CommittedBalance {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: CompressedRistretto,
    /// the amount of the given token stored in this balance
    pub amount: CompressedRistretto,
}

impl CommitVerifier for CommittedBalance {
    type VarType = BalanceVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        Ok(BalanceVar {
            mint: verifier.commit(self.mint),
            amount: verifier.commit(self.amount),
        })
    }
}

/// Represents a balance that has been allocated in an MPC network
#[derive(Clone, Debug)]
pub struct AuthenticatedBalance<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: AuthenticatedScalar<N, S>,
    /// the amount of the given token stored in this balance
    pub amount: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Balance {
    type SharedType = AuthenticatedBalance<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_u64s(owning_party, &[self.amount, self.mint])
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::SharedType {
            mint: shared_values[0].to_owned(),
            amount: shared_values[1].to_owned(),
        })
    }
}

/// Represents a balance that has been allocated in an MPC network
/// and committed to in a multi-prover constraint system
#[derive(Debug)]
pub struct AuthenticatedBalanceVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: MpcVariable<N, S>,
    /// the amount of the given token stored in this balance
    pub amount: MpcVariable<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedBalanceVar<N, S> {
    fn clone(&self) -> Self {
        Self {
            mint: self.mint.clone(),
            amount: self.amount.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedBalanceVar<N, S>>
    for Vec<MpcVariable<N, S>>
{
    fn from(balance: AuthenticatedBalanceVar<N, S>) -> Self {
        vec![balance.mint, balance.amount]
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S> for Balance {
    type SharedVarType = AuthenticatedBalanceVar<N, S>;
    type CommitType = AuthenticatedCommittedBalance<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinders = &[Scalar::random(rng), Scalar::random(rng)];
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[Scalar::from(self.mint), Scalar::from(self.amount)],
                blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedBalanceVar {
                mint: shared_vars[0].to_owned(),
                amount: shared_vars[1].to_owned(),
            },
            AuthenticatedCommittedBalance {
                mint: shared_comm[0].to_owned(),
                amount: shared_comm[1].to_owned(),
            },
        ))
    }
}

/// A balance that has been authenticated and committed in the network
#[derive(Clone, Debug)]
pub struct AuthenticatedCommittedBalance<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: AuthenticatedCompressedRistretto<N, S>,
    /// the amount of the given token stored in this balance
    pub amount: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedCommittedBalance<N, S>>
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    fn from(commit: AuthenticatedCommittedBalance<N, S>) -> Self {
        vec![commit.mint, commit.amount]
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedBalance<N, S>
{
    type VarType = BalanceVar;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        // Open the commitments
        let opened_commit = AuthenticatedCompressedRistretto::batch_open_and_authenticate(&[
            self.mint.clone(),
            self.amount.clone(),
        ])
        .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let mint_var = verifier.commit(opened_commit[0].value());
        let amount_var = verifier.commit(opened_commit[1].value());

        Ok(BalanceVar {
            mint: mint_var,
            amount: amount_var,
        })
    }
}
