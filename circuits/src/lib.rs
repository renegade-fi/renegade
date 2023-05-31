//! Groups circuits for MPC and zero knowledge execution
#![feature(generic_const_exprs)]
#![feature(negative_impls)]
#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use errors::{ProverError, VerifierError};
use merlin::Transcript;
use mpc::SharedFabric;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, Verifier},
    r1cs_mpc::{MpcProver, SharedR1CSProof},
    PedersenGens,
};
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use serde::{Deserialize, Serialize};

use rand_core::OsRng;

pub mod errors;
mod macro_tests;
pub mod mpc;
pub mod mpc_circuits;
pub mod mpc_gadgets;
mod tracing;
pub mod traits;
pub mod types;
pub mod zk_circuits;
pub mod zk_gadgets;

/// The maximum number of balances allowed in a wallet
pub const MAX_BALANCES: usize = 5;
/// The maximum number of fees a wallet may hold
pub const MAX_FEES: usize = 5;
/// The maximum number of orders allowed in a wallet
pub const MAX_ORDERS: usize = 5;
/// The highest possible set bit for a positive scalar
pub(crate) const POSITIVE_SCALAR_MAX_BITS: usize = 251;
/// The highest possible set bit in the Dalek scalar field
pub(crate) const SCALAR_MAX_BITS: usize = 253;
/// The seed for a fiat-shamir transcript
pub(crate) const TRANSCRIPT_SEED: &str = "merlin seed";

// ----------
// | Macros |
// ----------

/// A debug macro used for printing wires in a single-prover circuit during execution
#[allow(unused)]
macro_rules! print_wire {
    ($x:expr, $cs:ident) => {{
        use crypto::fields::scalar_to_biguint;
        use tracing::log;
        let x_eval = $cs.eval(&$x.into());
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
    }};
}

/// A debug macro used for printing wires in a raw MPC circuit during execution
#[allow(unused)]
macro_rules! print_mpc_wire {
    ($x:expr) => {{
        use crypto::fields::scalar_to_biguint;
        use tracing::log;
        let x_eval = $x.open().unwrap().to_scalar();
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
    }};
}

/// A debug macro used for printing wires in an MPC-ZK circuit during execution
#[allow(unused)]
macro_rules! print_multiprover_wire {
    ($x:expr, $cs:ident) => {{
        use crypto::fields::scalar_to_biguint;
        use tracing::log;
        let x_eval = $cs.eval(&$x.into()).unwrap().open().unwrap().to_scalar();
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
    }};
}

#[allow(unused)]
pub(crate) use print_mpc_wire;
#[allow(unused)]
pub(crate) use print_multiprover_wire;
#[allow(unused)]
pub(crate) use print_wire;
use traits::{
    CircuitBaseType, MultiProverCircuit, MultiproverCircuitBaseType,
    MultiproverCircuitCommitmentType, SingleProverCircuit,
};

// ------------------
// | Helper Methods |
// ------------------

/// Represents 2^m as a scalar
pub fn scalar_2_to_m(m: usize) -> Scalar {
    if m >= SCALAR_MAX_BITS {
        return Scalar::zero();
    }
    if (128..SCALAR_MAX_BITS).contains(&m) {
        Scalar::from(1u128 << 127) * Scalar::from(1u128 << (m - 127))
    } else {
        Scalar::from(1u128 << m)
    }
}

/// Abstracts over the flow of proving a single-prover circuit
pub fn singleprover_prove<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(<C::Witness as CircuitBaseType>::CommitmentType, R1CSProof), ProverError> {
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);

    C::prove(witness, statement, prover)
}

/// Abstracts over the flow of collaboratively proving a generic circuit
#[allow(clippy::type_complexity)]
pub fn multiprover_prove<'a, N, S, C>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: SharedFabric<N, S>,
) -> Result<
    (
        <C::Witness as MultiproverCircuitBaseType<N, S>>::MultiproverCommType,
        SharedR1CSProof<N, S>,
    ),
    ProverError,
>
where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    C: MultiProverCircuit<'a, N, S>,
{
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = MpcProver::new_with_fabric(fabric.0.clone(), &mut transcript, &pc_gens);

    // Prove the statement
    C::prove(witness, statement.clone(), fabric, prover)
}

/// Abstracts over the flow of verifying a proof for a single-prover proved circuit
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    witness_commitment: <C::Witness as CircuitBaseType>::CommitmentType,
    proof: R1CSProof,
) -> Result<(), VerifierError> {
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(witness_commitment, statement, proof, verifier)
}

/// Abstracts over the flow of verifying a proof for a collaboratively proved circuit
pub fn verify_collaborative_proof<'a, N, S, C>(
    statement: <C::Statement as MultiproverCircuitBaseType<N, S>>::BaseType,
    witness_commitment: <
        <C::Witness as MultiproverCircuitBaseType<N, S>>::MultiproverCommType as MultiproverCircuitCommitmentType<N, S>
        >::BaseCommitType,
    proof: R1CSProof,
) -> Result<(), VerifierError>
where
    C: MultiProverCircuit<'a, N, S>,
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
{
    // Verify the statement with a fresh transcript
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

    C::verify(witness_commitment, statement, proof, verifier)
}

// ---------
// | Types |
// ---------

/// A linkable commitment is a commitment used in multiple proofs. We split the constraints
/// of the matching engine into roughly 3 pieces:
///     1. Input validity checks, done offline by managing relayers (`VALID COMMITMENTS`)
///     2. The matching engine execution, proved collaboratively over an MPC fabric (`VALID MATCH MPC`)
///     3. Output validity checks: i.e. note construction and encryption (`VALID MATCH ENCRYPTION`)
/// These components are split to remove as many constraints from the bottleneck (the collaborative proof)
/// as possible.
///
/// However, we need to ensure that -- for example -- the order used in the proof of `VALID COMMITMENTS`
/// is the same order as the order used in `VALID MATCH MPC`. This can be done by constructing the Pedersen
/// commitments to the orders using the same randomness across proofs. That way, the verified may use the
/// shared Pedersen commitment as an implicit constraint that witness values are equal across proofs.
///
/// The `LinkableCommitment` type allows this from the prover side by storing the randomness used in the
/// original commitment along with the value itself.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LinkableCommitment {
    /// The underlying value committed to
    pub val: Scalar,
    /// The randomness used to blind the commitment
    randomness: Scalar,
}

impl LinkableCommitment {
    /// Create a new linkable commitment from a given value
    pub fn new(val: Scalar) -> Self {
        // Choose a random blinder
        let mut rng = OsRng {};
        let randomness = Scalar::random(&mut rng);
        Self { val, randomness }
    }

    /// Get the Pedersen commitment to this value
    pub fn compute_commitment(&self) -> CompressedRistretto {
        let pedersen_generators = PedersenGens::default();
        pedersen_generators
            .commit(self.val, self.randomness)
            .compress()
    }
}

impl From<Scalar> for LinkableCommitment {
    fn from(val: Scalar) -> Self {
        LinkableCommitment::new(val)
    }
}

impl From<LinkableCommitment> for Scalar {
    fn from(comm: LinkableCommitment) -> Self {
        comm.val
    }
}

/// A linkable commitment that has been allocated inside of an MPC fabric
#[derive(Debug)]
pub struct AuthenticatedLinkableCommitment<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The underlying shared scalar
    pub(crate) val: AuthenticatedScalar<N, S>,
    /// The randomness used to blind the commitment
    pub(crate) randomness: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedLinkableCommitment<N, S>
{
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
            randomness: self.randomness.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> AuthenticatedLinkableCommitment<N, S> {
    /// Create a linkable commitment from a shared scalar by sampling a shared
    /// blinder
    pub fn new(val: AuthenticatedScalar<N, S>, randomness: AuthenticatedScalar<N, S>) -> Self {
        Self { val, randomness }
    }
}

// ----------------
// | Test Helpers |
// ----------------
#[cfg(test)]
pub(crate) mod test_helpers {
    use crypto::fields::{prime_field_to_bigint, scalar_to_bigint, DalekRistrettoField};
    use curve25519_dalek::scalar::Scalar;
    use env_logger::{Builder, Env, Target};
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{Prover, Verifier},
        PedersenGens,
    };

    use crate::{errors::VerifierError, traits::SingleProverCircuit};

    const TRANSCRIPT_SEED: &str = "test";

    // ---------
    // | Setup |
    // ---------

    /// Constructor to initialize logging in tests
    #[ctor::ctor]
    fn setup() {
        init_logger()
    }

    pub fn init_logger() {
        let env = Env::default().filter_or("MY_CRATE_LOG", "trace");

        let mut builder = Builder::from_env(env);
        builder.target(Target::Stdout);

        builder.init();
    }

    // -----------
    // | Helpers |
    // -----------

    /// Compares a Dalek Scalar to an Arkworks field element
    pub(crate) fn compare_scalar_to_felt(scalar: &Scalar, felt: &DalekRistrettoField) -> bool {
        scalar_to_bigint(scalar).eq(&prime_field_to_bigint(felt))
    }

    /// Abstracts over the flow of proving and verifying a circuit given
    /// a valid statement + witness assignment
    pub fn bulletproof_prove_and_verify<C: SingleProverCircuit>(
        witness: C::Witness,
        statement: C::Statement,
    ) -> Result<(), VerifierError> {
        let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let prover = Prover::new(&pc_gens, &mut transcript);

        // Prove the statement
        let (witness_commitment, proof) = C::prove(witness, statement.clone(), prover).unwrap();

        // Verify the statement with a fresh transcript
        let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

        C::verify(witness_commitment, statement, proof, verifier)
    }
}

/// Groups helpers that operate on native types; which correspond to circuitry
/// defined in this library
///
/// For example; when computing witnesses, wallet commitments, note commitments,
/// nullifiers, etc are all useful helpers
pub mod native_helpers {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{prime_field_to_scalar, scalar_to_prime_field, DalekRistrettoField},
        hash::{default_poseidon_params, evaluate_hash_chain},
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;

    use crate::{
        traits::BaseType,
        types::wallet::{Nullifier, Wallet, WalletShare, WalletShareStateCommitment},
    };

    /// Recover a wallet from blinded secret shares
    pub fn wallet_from_blinded_shares<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let recovered_blinder = private_shares.blinder + public_shares.blinder;
        let unblinded_public_shares = public_shares.unblind_shares(recovered_blinder);
        private_shares + unblinded_public_shares
    }

    /// Compute the hash of the randomness of a given wallet
    pub fn compute_poseidon_hash(values: &[Scalar]) -> Scalar {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&values.iter().map(scalar_to_prime_field).collect_vec());

        let out: DalekRistrettoField = hasher.squeeze_field_elements(1 /* num_elements */)[0];
        prime_field_to_scalar(&out)
    }

    /// Compute a commitment to the shares of a wallet
    pub fn compute_wallet_share_commitment<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> WalletShareStateCommitment
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Hash the private input, then append the public input and re-hash
        let private_input_commitment = compute_wallet_private_share_commitment(private_shares);
        let mut hash_input = vec![private_input_commitment];
        hash_input.append(&mut public_shares.to_scalars());

        compute_poseidon_hash(&hash_input)
    }

    /// Compute a commitment to a single share of a wallet
    pub fn compute_wallet_private_share_commitment<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        private_share: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Scalar
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        compute_poseidon_hash(&private_share.to_scalars())
    }

    /// Compute a commitment to the full shares of a wallet, given a commitment
    /// to only the private shares
    pub fn compute_wallet_commitment_from_private<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_share_comm: WalletShareStateCommitment,
    ) -> WalletShareStateCommitment
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let mut hash_input = vec![private_share_comm];
        hash_input.append(&mut public_shares.to_scalars());
        compute_poseidon_hash(&hash_input)
    }

    /// Compute the nullifier of a set of wallet shares
    pub fn compute_wallet_share_nullifier(
        share_commitment: WalletShareStateCommitment,
        wallet_blinder: Scalar,
    ) -> Nullifier {
        compute_poseidon_hash(&[share_commitment, wallet_blinder])
    }

    /// Reblind a wallet given its secret shares
    ///
    /// Returns the reblinded private and public shares
    pub fn reblind_wallet<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        private_secret_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Sample new wallet blinders from the `blinder` CSPRNG
        // See the comments in `valid_reblind.rs` for an explanation of the two CSPRNGs
        let mut blinder_samples =
            evaluate_hash_chain(private_secret_shares.blinder, 2 /* length */);
        let mut blinder_drain = blinder_samples.drain(..);
        let new_blinder = blinder_drain.next().unwrap();
        let new_blinder_private_share = blinder_drain.next().unwrap();

        // Sample new secret shares for the wallet
        let shares_serialized: Vec<Scalar> = private_secret_shares.to_scalars();
        let serialized_len = shares_serialized.len();
        let mut secret_shares =
            evaluate_hash_chain(shares_serialized[serialized_len - 2], serialized_len - 1);
        secret_shares.push(new_blinder_private_share);

        create_wallet_shares_with_randomness(
            wallet,
            new_blinder,
            new_blinder_private_share,
            secret_shares,
        )
    }

    /// Construct public shares of a wallet given the private shares and blinder
    ///
    /// The return type is a tuple containing the private and public shares. Note
    /// that the private shares returned are exactly those passed in
    pub fn create_wallet_shares_from_private<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        blinder: Scalar,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Serialize the wallet's private shares and use this as the secret share stream
        let private_shares_ser: Vec<Scalar> = private_shares.clone().to_scalars();
        create_wallet_shares_with_randomness(
            wallet,
            blinder,
            private_shares.blinder,
            private_shares_ser,
        )
    }

    /// Create a secret sharing of a wallet given the secret shares and blinders
    pub fn create_wallet_shares_with_randomness<
        T,
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        blinder: Scalar,
        private_blinder_share: Scalar,
        secret_shares: T,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        T: IntoIterator<Item = Scalar>,
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        let share_iter = secret_shares.into_iter();
        let wallet_scalars = wallet.to_scalars();
        let wallet_private_shares = share_iter.take(wallet_scalars.len()).collect_vec();
        let wallet_public_shares = wallet_scalars
            .iter()
            .zip_eq(wallet_private_shares.iter())
            .map(|(scalar, private_share)| scalar - private_share)
            .collect_vec();

        let mut private_shares = WalletShare::from_scalars(&mut wallet_private_shares.into_iter());
        let mut public_shares = WalletShare::from_scalars(&mut wallet_public_shares.into_iter());
        private_shares.blinder = private_blinder_share;
        public_shares.blinder = blinder - private_blinder_share;

        let blinded_public_shares = public_shares.blind_shares(blinder);

        (private_shares, blinded_public_shares)
    }
}

#[cfg(test)]
mod circuits_test {
    use crypto::fields::bigint_to_scalar;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng};

    use crate::scalar_2_to_m;

    #[test]
    fn test_scalar_2_to_m() {
        let rand_m: usize = thread_rng().gen_range(0..256);
        let res = scalar_2_to_m(rand_m);

        let expected = bigint_to_scalar(&(BigInt::from(1u64) << rand_m));
        assert_eq!(res, expected);
    }
}
