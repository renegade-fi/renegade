//! Groups base and derived types for the `Balance` object

use crypto::fields::biguint_to_scalar;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use mpc_bulletproof::{
    r1cs::{Prover, Variable, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::MpcError, mpc::SharedFabric, Allocate, CommitProver, CommitSharedProver,
    CommitVerifier, LinkableCommitment,
};

/// Represents the base type of a balance in tuple holding a reference to the
/// ERC-20 token and its amount
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// The mint (ERC-20 token address) of the token in the balance
    pub mint: BigUint,
    /// The amount of the given token stored in this balance
    pub amount: u64,
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
        let (mint_comm, mint_var) =
            prover.commit(biguint_to_scalar(&self.mint), Scalar::random(rng));
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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

/// Represents a balance that may be linked across proofs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkableBalanceCommitment {
    /// The mint (erc-20 token address) of the token in this balance
    pub mint: LinkableCommitment,
    /// The amount of the token held by this balance
    pub amount: LinkableCommitment,
}

impl From<Balance> for LinkableBalanceCommitment {
    fn from(balance: Balance) -> Self {
        Self {
            mint: LinkableCommitment::new(biguint_to_scalar(&balance.mint)),
            amount: LinkableCommitment::new(balance.amount.into()),
        }
    }
}

impl CommitProver for LinkableBalanceCommitment {
    type VarType = BalanceVar;
    type CommitType = CommittedBalance;
    type ErrorType = ();

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (mint_var, mint_comm) = self.mint.commit_prover(rng, prover).unwrap();
        let (amount_var, amount_comm) = self.amount.commit_prover(rng, prover).unwrap();

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
        let mint_scalar = biguint_to_scalar(&self.mint);
        let amount_scalar = Scalar::from(self.amount);

        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_scalars(owning_party, &[mint_scalar, amount_scalar])
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
                &[biguint_to_scalar(&self.mint), Scalar::from(self.amount)],
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
