//! Groups the base type and derived types for the `Fee` entity
use std::ops::Add;

use crate::{
    errors::{MpcError, TypeConversionError},
    mpc::SharedFabric,
    types::{biguint_from_hex_string, biguint_to_hex_string},
    zk_gadgets::fixed_point::{
        AuthenticatedCommittedFixedPoint, AuthenticatedFixedPoint, AuthenticatedFixedPointVar,
        CommittedFixedPoint, FixedPoint, FixedPointVar, LinkableFixedPointCommitment,
    },
    Allocate, CommitPublic, CommitSharedProver, CommitVerifier, CommitWitness, LinkableCommitment,
    SharePublic,
};
use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, Variable, Verifier},
    r1cs_mpc::{MpcLinearCombination, MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// -----------------
// | Fee Base Type |
// -----------------

/// Represents a fee-tuple in the state, i.e. a commitment to pay a relayer for a given
/// match
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fee {
    /// The public settle key of the cluster collecting fees
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub settle_key: BigUint,
    /// The mint (ERC-20 Address) of the token used to pay gas
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub gas_addr: BigUint,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: u64,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: FixedPoint,
}

impl Fee {
    /// Whether or not the given instance is a default fee
    pub fn is_default(&self) -> bool {
        self.eq(&Fee::default())
    }
}

impl TryFrom<&[u64]> for Fee {
    type Error = TypeConversionError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        if values.len() != 4 {
            return Err(TypeConversionError(format!(
                "expected array of length 4, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            settle_key: BigUint::from(values[0]),
            gas_addr: BigUint::from(values[1]),
            gas_token_amount: values[2],
            // Re-represent the underlying fixed-point representation as a u64, simply be re-interpreting
            // the bytes
            percentage_fee: Scalar::from(values[3]).into(),
        })
    }
}

impl From<&Fee> for Vec<u64> {
    fn from(fee: &Fee) -> Self {
        vec![
            fee.settle_key.clone().try_into().unwrap(),
            fee.gas_addr.clone().try_into().unwrap(),
            fee.gas_token_amount,
            // Re-represent the underlying fixed-point representation as a u64, simply be re-interpreting
            // the bytes
            scalar_to_u64(&fee.percentage_fee.repr),
        ]
    }
}

/// A fee with values allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct FeeVar<L: Into<LinearCombination>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: L,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: L,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: L,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: FixedPointVar,
}

impl<L: Into<LinearCombination>> From<FeeVar<L>> for Vec<LinearCombination> {
    fn from(fee: FeeVar<L>) -> Self {
        vec![
            fee.settle_key.into(),
            fee.gas_addr.into(),
            fee.gas_token_amount.into(),
            fee.percentage_fee.repr,
        ]
    }
}

impl CommitWitness for Fee {
    type VarType = FeeVar<Variable>;
    type CommitType = CommittedFee;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (settle_comm, settle_var) =
            prover.commit(biguint_to_scalar(&self.settle_key), Scalar::random(rng));
        let (addr_comm, addr_var) =
            prover.commit(biguint_to_scalar(&self.gas_addr), Scalar::random(rng));
        let (amount_comm, amount_var) =
            prover.commit(Scalar::from(self.gas_token_amount), Scalar::random(rng));
        let (percent_var, percent_comm) = self.percentage_fee.commit_witness(rng, prover).unwrap();

        Ok((
            FeeVar {
                settle_key: settle_var,
                gas_addr: addr_var,
                gas_token_amount: amount_var,
                percentage_fee: percent_var,
            },
            CommittedFee {
                settle_key: settle_comm,
                gas_addr: addr_comm,
                gas_token_amount: amount_comm,
                percentage_fee: percent_comm,
            },
        ))
    }
}

/// A fee that has been committed to in a single-prover constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedFee {
    /// The public settle key of the cluster collecting fees
    pub settle_key: CompressedRistretto,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: CompressedRistretto,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: CompressedRistretto,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: CommittedFixedPoint,
}

impl CommitVerifier for CommittedFee {
    type VarType = FeeVar<Variable>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let settle_var = verifier.commit(self.settle_key);
        let addr_var = verifier.commit(self.gas_addr);
        let amount_var = verifier.commit(self.gas_token_amount);
        let percentage_var = self.percentage_fee.commit_verifier(verifier).unwrap();

        Ok(FeeVar {
            settle_key: settle_var,
            gas_addr: addr_var,
            gas_token_amount: amount_var,
            percentage_fee: percentage_var,
        })
    }
}

// ------------------------------
// | Commitment Linked Fee Type |
// ------------------------------

/// A fee that can be linked across proofs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkableFeeCommitment {
    /// The public settle key of the cluster collecting fees
    pub settle_key: LinkableCommitment,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: LinkableCommitment,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: LinkableCommitment,
    /// The percentage fee that the cluster may take upon match
    pub percentage_fee: LinkableFixedPointCommitment,
}

impl From<Fee> for LinkableFeeCommitment {
    fn from(fee: Fee) -> Self {
        Self {
            settle_key: LinkableCommitment::new(biguint_to_scalar(&fee.settle_key)),
            gas_addr: LinkableCommitment::new(biguint_to_scalar(&fee.gas_addr)),
            gas_token_amount: LinkableCommitment::new(fee.gas_token_amount.into()),
            percentage_fee: fee.percentage_fee.into(),
        }
    }
}

impl CommitWitness for LinkableFeeCommitment {
    type VarType = FeeVar<Variable>;
    type CommitType = CommittedFee;
    type ErrorType = ();

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (key_var, key_comm) = self.settle_key.commit_witness(rng, prover).unwrap();
        let (gas_addr_var, gas_addr_comm) = self.gas_addr.commit_witness(rng, prover).unwrap();
        let (gas_amount_var, gas_amount_comm) =
            self.gas_token_amount.commit_witness(rng, prover).unwrap();
        let (percent_fee_var, percent_fee_comm) =
            self.percentage_fee.commit_witness(rng, prover).unwrap();

        Ok((
            FeeVar {
                settle_key: key_var,
                gas_addr: gas_addr_var,
                gas_token_amount: gas_amount_var,
                percentage_fee: percent_fee_var,
            },
            CommittedFee {
                settle_key: key_comm,
                gas_addr: gas_addr_comm,
                gas_token_amount: gas_amount_comm,
                percentage_fee: percent_fee_comm,
            },
        ))
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> SharePublic<N, S>
    for LinkableFeeCommitment
{
    type ErrorType = MpcError;

    fn share_public(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self, Self::ErrorType> {
        let values = &[
            self.settle_key.val,
            self.settle_key.randomness,
            self.gas_addr.val,
            self.gas_addr.randomness,
            self.gas_token_amount.val,
            self.gas_token_amount.randomness,
            self.percentage_fee.repr.val,
            self.percentage_fee.repr.randomness,
        ];
        let shared_values = fabric
            .borrow_fabric()
            .batch_shared_plaintext_scalars(owning_party, values)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self {
            settle_key: LinkableCommitment {
                val: shared_values[0].to_owned(),
                randomness: shared_values[1].to_owned(),
            },
            gas_addr: LinkableCommitment {
                val: shared_values[2].to_owned(),
                randomness: shared_values[3].to_owned(),
            },
            gas_token_amount: LinkableCommitment {
                val: shared_values[4].to_owned(),
                randomness: shared_values[5].to_owned(),
            },
            percentage_fee: LinkableFixedPointCommitment {
                repr: LinkableCommitment {
                    val: shared_values[6].to_owned(),
                    randomness: shared_values[7].to_owned(),
                },
            },
        })
    }
}

// -----------------
// | MPC Fee Types |
// -----------------

/// A fee with values that have been allocated in an MPC network
#[derive(Clone, Debug)]
pub struct AuthenticatedFee<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: AuthenticatedScalar<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: AuthenticatedScalar<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: AuthenticatedScalar<N, S>,
    /// The percentage fee that the cluster may take upon match
    pub percentage_fee: AuthenticatedFixedPoint<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedFee<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(fee: AuthenticatedFee<N, S>) -> Self {
        vec![
            fee.settle_key,
            fee.gas_addr,
            fee.gas_token_amount,
            fee.percentage_fee.repr,
        ]
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedFee<N, S>
{
    fn from(values: &[AuthenticatedScalar<N, S>]) -> Self {
        Self {
            settle_key: values[0].to_owned(),
            gas_addr: values[1].to_owned(),
            gas_token_amount: values[2].to_owned(),
            percentage_fee: AuthenticatedFixedPoint {
                repr: values[3].to_owned(),
            },
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Fee {
    type SharedType = AuthenticatedFee<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_scalars(
                owning_party,
                &[
                    biguint_to_scalar(&self.settle_key),
                    biguint_to_scalar(&self.gas_addr),
                    Scalar::from(self.gas_token_amount),
                    Scalar::from(self.percentage_fee),
                ],
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(AuthenticatedFee {
            settle_key: shared_values[0].to_owned(),
            gas_addr: shared_values[1].to_owned(),
            gas_token_amount: shared_values[2].to_owned(),
            percentage_fee: AuthenticatedFixedPoint {
                repr: shared_values[3].to_owned(),
            },
        })
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> SharePublic<N, S> for Fee {
    type ErrorType = MpcError;

    fn share_public(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_shared_plaintext_scalars(
                owning_party,
                &[
                    biguint_to_scalar(&self.settle_key),
                    biguint_to_scalar(&self.gas_addr),
                    Scalar::from(self.gas_token_amount),
                    Scalar::from(self.percentage_fee),
                ],
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Fee {
            settle_key: scalar_to_biguint(&shared_values[0].to_owned()),
            gas_addr: scalar_to_biguint(&shared_values[1].to_owned()),
            gas_token_amount: scalar_to_u64(&shared_values[2]),
            percentage_fee: FixedPoint {
                repr: shared_values[3].to_owned(),
            },
        })
    }
}

/// Represents a fee that has been allocated in an MPC network and committed to in
/// a multi-prover constraint system
#[derive(Debug)]
pub struct AuthenticatedFeeVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: MpcVariable<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: MpcVariable<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: MpcVariable<N, S>,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: AuthenticatedFixedPointVar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedFeeVar<N, S> {
    fn clone(&self) -> Self {
        Self {
            settle_key: self.settle_key.clone(),
            gas_addr: self.gas_addr.clone(),
            gas_token_amount: self.gas_token_amount.clone(),
            percentage_fee: self.percentage_fee.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedFeeVar<N, S>>
    for Vec<MpcLinearCombination<N, S>>
{
    fn from(fee: AuthenticatedFeeVar<N, S>) -> Self {
        vec![
            fee.settle_key.into(),
            fee.gas_addr.into(),
            fee.gas_token_amount.into(),
            fee.percentage_fee.repr,
        ]
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S> for Fee {
    type SharedVarType = AuthenticatedFeeVar<N, S>;
    type CommitType = AuthenticatedCommittedFee<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinders = (0..4).map(|_| Scalar::random(rng)).collect_vec();
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    biguint_to_scalar(&self.settle_key),
                    biguint_to_scalar(&self.gas_addr),
                    Scalar::from(self.gas_token_amount),
                    Scalar::from(self.percentage_fee),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedFeeVar {
                settle_key: shared_vars[0].to_owned(),
                gas_addr: shared_vars[1].to_owned(),
                gas_token_amount: shared_vars[2].to_owned(),
                percentage_fee: AuthenticatedFixedPointVar {
                    repr: shared_vars[3].to_owned().into(),
                },
            },
            AuthenticatedCommittedFee {
                settle_key: shared_comm[0].to_owned(),
                gas_addr: shared_comm[1].to_owned(),
                gas_token_amount: shared_comm[2].to_owned(),
                percentage_fee: AuthenticatedCommittedFixedPoint {
                    repr: shared_comm[3].to_owned(),
                },
            },
        ))
    }
}

/// Represents a fee that has been committed to in a multi-prover constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedCommittedFee<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: AuthenticatedCompressedRistretto<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: AuthenticatedCompressedRistretto<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: AuthenticatedCompressedRistretto<N, S>,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: AuthenticatedCommittedFixedPoint<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedCommittedFee<N, S>>
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    fn from(commit: AuthenticatedCommittedFee<N, S>) -> Self {
        vec![
            commit.settle_key,
            commit.gas_addr,
            commit.gas_token_amount,
            commit.percentage_fee.repr,
        ]
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedFee<N, S>
{
    type VarType = FeeVar<Variable>;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let opened_values = AuthenticatedCompressedRistretto::batch_open_and_authenticate(&[
            self.settle_key.clone(),
            self.gas_addr.clone(),
            self.gas_token_amount.clone(),
            self.percentage_fee.repr.clone(),
        ])
        .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let settle_var = verifier.commit(opened_values[0].value());
        let addr_var = verifier.commit(opened_values[1].value());
        let amount_var = verifier.commit(opened_values[2].value());
        let percentage_var = verifier.commit(opened_values[3].value());

        Ok(FeeVar {
            settle_key: settle_var,
            gas_addr: addr_var,
            gas_token_amount: amount_var,
            percentage_fee: FixedPointVar {
                repr: percentage_var.into(),
            },
        })
    }
}

// -------------------------
// | Secret Share Fee Type |
// -------------------------

/// Represents an additive secret share of a fee
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeSecretShare {
    /// The public settle key of the cluster collecting fees
    pub settle_key: Scalar,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: Scalar,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: Scalar,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: Scalar,
}

impl FeeSecretShare {
    /// The number of `Scalar`s needed to represent a fee secret shares
    pub const SHARES_PER_FEE: usize = 4;

    /// Apply a blinder to the secret shares
    pub fn blind(&mut self, blinder: Scalar) {
        self.settle_key += blinder;
        self.gas_addr += blinder;
        self.gas_token_amount += blinder;
        self.percentage_fee += blinder;
    }

    /// Remove a blinder from the secret shares
    pub fn unblind(&mut self, blinder: Scalar) {
        self.settle_key -= blinder;
        self.gas_addr -= blinder;
        self.gas_token_amount -= blinder;
        self.percentage_fee -= blinder;
    }
}

impl Add<FeeSecretShare> for FeeSecretShare {
    type Output = Fee;

    fn add(self, rhs: FeeSecretShare) -> Self::Output {
        let settle_key = scalar_to_biguint(&(self.settle_key + rhs.settle_key));
        let gas_addr = scalar_to_biguint(&(self.gas_addr + rhs.gas_addr));
        let gas_token_amount = scalar_to_u64(&(self.gas_token_amount + rhs.gas_token_amount));
        let percentage_fee = FixedPoint::from(self.percentage_fee + rhs.percentage_fee);

        Fee {
            settle_key,
            gas_addr,
            gas_token_amount,
            percentage_fee,
        }
    }
}

// Fee share serialization
impl From<FeeSecretShare> for Vec<Scalar> {
    fn from(fee: FeeSecretShare) -> Self {
        vec![
            fee.settle_key,
            fee.gas_addr,
            fee.gas_token_amount,
            fee.percentage_fee,
        ]
    }
}

// Fee share deserialization
impl From<Vec<Scalar>> for FeeSecretShare {
    fn from(mut serialized: Vec<Scalar>) -> Self {
        let mut drain = serialized.drain(..);
        FeeSecretShare {
            settle_key: drain.next().unwrap(),
            gas_addr: drain.next().unwrap(),
            gas_token_amount: drain.next().unwrap(),
            percentage_fee: drain.next().unwrap(),
        }
    }
}

/// Represents a fee secret share that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct FeeSecretShareVar {
    /// The public settle key of the cluster collecting fees
    pub settle_key: LinearCombination,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: LinearCombination,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: LinearCombination,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: LinearCombination,
}

impl FeeSecretShareVar {
    /// Apply a blinder to the secret shares
    pub fn blind(&mut self, blinder: LinearCombination) {
        self.settle_key += blinder.clone();
        self.gas_addr += blinder.clone();
        self.gas_token_amount += blinder.clone();
        self.percentage_fee += blinder;
    }

    /// Remove a blinder from the secret shares
    pub fn unblind(&mut self, blinder: LinearCombination) {
        self.settle_key -= blinder.clone();
        self.gas_addr -= blinder.clone();
        self.gas_token_amount -= blinder.clone();
        self.percentage_fee -= blinder;
    }
}

impl Add<FeeSecretShareVar> for FeeSecretShareVar {
    type Output = FeeVar<LinearCombination>;

    fn add(self, rhs: FeeSecretShareVar) -> Self::Output {
        FeeVar {
            settle_key: self.settle_key + rhs.settle_key,
            gas_addr: self.gas_addr + rhs.gas_addr,
            gas_token_amount: self.gas_token_amount + rhs.gas_token_amount,
            percentage_fee: FixedPointVar {
                repr: self.percentage_fee + rhs.percentage_fee,
            },
        }
    }
}

// Fee share serialization
impl From<FeeSecretShareVar> for Vec<LinearCombination> {
    fn from(fee: FeeSecretShareVar) -> Self {
        vec![
            fee.settle_key,
            fee.gas_addr,
            fee.gas_token_amount,
            fee.percentage_fee,
        ]
    }
}

// Fee share deserialization
impl<L: Into<LinearCombination>> From<Vec<L>> for FeeSecretShareVar {
    fn from(mut serialized: Vec<L>) -> Self {
        let mut drain = serialized.drain(..);
        FeeSecretShareVar {
            settle_key: drain.next().unwrap().into(),
            gas_addr: drain.next().unwrap().into(),
            gas_token_amount: drain.next().unwrap().into(),
            percentage_fee: drain.next().unwrap().into(),
        }
    }
}

/// Represents a commitment to a fee secret share that has been allocated in a constraint system
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FeeSecretShareCommitment {
    /// The public settle key of the cluster collecting fees
    pub settle_key: CompressedRistretto,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: CompressedRistretto,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: CompressedRistretto,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: CompressedRistretto,
}

impl CommitWitness for FeeSecretShare {
    type VarType = FeeSecretShareVar;
    type CommitType = FeeSecretShareCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (settle_key_var, settle_key_comm) =
            self.settle_key.commit_witness(rng, prover).unwrap();
        let (gas_addr_var, gas_addr_comm) = self.gas_addr.commit_witness(rng, prover).unwrap();
        let (gas_amount_var, gas_amount_comm) =
            self.gas_token_amount.commit_witness(rng, prover).unwrap();
        let (percentage_var, percentage_comm) =
            self.percentage_fee.commit_witness(rng, prover).unwrap();

        Ok((
            FeeSecretShareVar {
                settle_key: settle_key_var.into(),
                gas_addr: gas_addr_var.into(),
                gas_token_amount: gas_amount_var.into(),
                percentage_fee: percentage_var.into(),
            },
            FeeSecretShareCommitment {
                settle_key: settle_key_comm,
                gas_addr: gas_addr_comm,
                gas_token_amount: gas_amount_comm,
                percentage_fee: percentage_comm,
            },
        ))
    }
}

impl CommitPublic for FeeSecretShare {
    type VarType = FeeSecretShareVar;
    type ErrorType = ();

    fn commit_public<CS: mpc_bulletproof::r1cs::RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let settle_key_var = self.settle_key.commit_public(cs).unwrap();
        let gas_addr_var = self.gas_addr.commit_public(cs).unwrap();
        let gas_amount_var = self.gas_token_amount.commit_public(cs).unwrap();
        let percentage_var = self.percentage_fee.commit_public(cs).unwrap();

        Ok(FeeSecretShareVar {
            settle_key: settle_key_var.into(),
            gas_addr: gas_addr_var.into(),
            gas_token_amount: gas_amount_var.into(),
            percentage_fee: percentage_var.into(),
        })
    }
}

impl CommitVerifier for FeeSecretShareCommitment {
    type VarType = FeeSecretShareVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let settle_key_var = self.settle_key.commit_verifier(verifier).unwrap();
        let gas_addr_var = self.gas_addr.commit_verifier(verifier).unwrap();
        let gas_amount_var = self.gas_token_amount.commit_verifier(verifier).unwrap();
        let percentage_var = self.percentage_fee.commit_verifier(verifier).unwrap();

        Ok(FeeSecretShareVar {
            settle_key: settle_key_var.into(),
            gas_addr: gas_addr_var.into(),
            gas_token_amount: gas_amount_var.into(),
            percentage_fee: percentage_var.into(),
        })
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{LinearCombination, Prover},
        PedersenGens,
    };

    use crate::{
        test_helpers::{assert_lcs_equal, random_scalar},
        types::fee::FeeSecretShareVar,
        CommitPublic,
    };

    use super::FeeSecretShare;

    /// Tests serialization and deserialization of fee secret share types
    #[test]
    fn test_fee_share_serde() {
        let fee_share = FeeSecretShare {
            settle_key: random_scalar(),
            gas_addr: random_scalar(),
            gas_token_amount: random_scalar(),
            percentage_fee: random_scalar(),
        };

        // Serialize then deserialize
        let serialized: Vec<Scalar> = fee_share.into();
        let deserialized: FeeSecretShare = serialized.into();

        assert_eq!(fee_share, deserialized);

        // Allocate in a constraint system then test on allocated types
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let fee_share_var = fee_share.commit_public(&mut prover).unwrap();
        let serialized: Vec<LinearCombination> = fee_share_var.clone().into();
        let deserialized: FeeSecretShareVar = serialized.into();

        assert_lcs_equal(&fee_share_var.settle_key, &deserialized.settle_key, &prover);
        assert_lcs_equal(&fee_share_var.gas_addr, &deserialized.gas_addr, &prover);
        assert_lcs_equal(
            &fee_share_var.gas_token_amount,
            &deserialized.gas_token_amount,
            &prover,
        );
        assert_lcs_equal(
            &fee_share_var.percentage_fee,
            &deserialized.percentage_fee,
            &prover,
        );
    }
}
