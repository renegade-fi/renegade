//! Groups circuitry for full zero knowledge circuits that we are interested
//! in proving knowledge of witness for throughout the network
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

pub mod proof_linking;
pub mod valid_commitments;
pub mod valid_match_settle;
pub mod valid_reblind;
pub mod valid_wallet_create;
pub mod valid_wallet_update;

use circuit_types::{
    traits::{
        BaseType, CircuitBaseType, MpcType, MultiProverCircuit, MultiproverCircuitBaseType,
        SingleProverCircuit,
    },
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::Scalar;
use itertools::Itertools;
use mpc_relation::{proof_linking::LinkableCircuit, traits::Circuit};

/// The group name for the VALID REBLIND <-> VALID COMMITMENTS link
pub const VALID_REBLIND_COMMITMENTS_LINK: &str = "valid_reblind_commitments";
/// The group for the VALID COMMITMENTS <-> VALID MATCH SETTLE (party 0) link
pub const VALID_COMMITMENTS_MATCH_SETTLE_LINK0: &str = "valid_commitments_match_settle0";
/// The group for the VALID COMMITMENTS <-> VALID MATCH SETTLE (party 1) link
pub const VALID_COMMITMENTS_MATCH_SETTLE_LINK1: &str = "valid_commitments_match_settle1";

// -----------
// | Helpers |
// -----------

/// Check whether a witness and statement satisfy wire assignments for a
/// circuit
pub fn check_constraint_satisfaction<C: SingleProverCircuit>(
    witness: &C::Witness,
    statement: &C::Statement,
) -> bool {
    // Apply the constraints
    let mut cs = PlonkCircuit::new_turbo_plonk();
    let circuit_layout = C::get_circuit_layout().unwrap();
    for (id, layout) in circuit_layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(layout));
    }

    let witness_var = witness.create_witness(&mut cs);
    let statement_var = statement.create_public_var(&mut cs);

    C::apply_constraints(witness_var, statement_var, &mut cs).unwrap();

    // Check for satisfaction
    let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
    cs.check_circuit_satisfiability(&statement_scalars).is_ok()
}

/// Check whether a witness and statement satisfy wire assignments for a
/// multiprover circuit
pub fn check_constraint_satisfaction_multiprover<C: MultiProverCircuit>(
    witness: &C::Witness,
    statement: &C::Statement,
    fabric: &Fabric,
) -> bool {
    let mut cs = MpcPlonkCircuit::new(fabric.clone());
    let circuit_layout = C::get_circuit_layout().unwrap();
    for (id, layout) in circuit_layout.group_layouts.into_iter() {
        cs.create_link_group(id, Some(layout));
    }

    let witness_var = witness.create_shared_witness(&mut cs);
    let statement_var = statement.create_shared_public_var(&mut cs);

    C::apply_constraints_multiprover(witness_var, statement_var, fabric, &mut cs).unwrap();

    // Check for satisfaction
    let statement_scalars = statement.to_authenticated_scalars();
    cs.check_circuit_satisfiability(&statement_scalars).is_ok()
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use std::iter::from_fn;

    use circuit_types::{
        balance::Balance,
        fixed_point::FixedPoint,
        keychain::{NonNativeScalar, PublicKeyChain, PublicSigningKey, NUM_KEYS},
        merkle::MerkleOpening,
        order::{Order, OrderSide},
        wallet::{Wallet, WalletShare},
    };
    use constants::Scalar;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use renegade_crypto::hash::compute_poseidon_hash;

    use circuit_types::native_helpers::create_wallet_shares_with_randomness;

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        // The key data for the wallet, note that only the identification keys are currently
        // computed correctly
        pub static ref PRIVATE_KEYS: Vec<Scalar> = vec![Scalar::one(); NUM_KEYS];
        pub static ref PUBLIC_KEYS: PublicKeyChain = PublicKeyChain {
            pk_root: PublicSigningKey {
                x: NonNativeScalar::from(&BigUint::from(2u8).pow(256)),
                y: NonNativeScalar::from(&BigUint::from(2u8).pow(256)),
            },
            pk_match: compute_poseidon_hash(&[PRIVATE_KEYS[1]]).into(),
        };
        pub static ref INITIAL_BALANCES: [Balance; MAX_BALANCES] = [
            Balance { mint: 1u8.into(), amount: 5, relayer_fee_balance: 0, protocol_fee_balance: 0 },
            Balance {
                mint: 2u8.into(),
                amount: 10,
                relayer_fee_balance: 0,
                protocol_fee_balance: 0
            }
        ];
        pub static ref INITIAL_ORDERS: [Order; MAX_ORDERS] = [
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: OrderSide::Buy,
                amount: 1,
                // No price limit by default
                worst_case_price: FixedPoint::from_integer(100000),
                timestamp: TIMESTAMP,
            },
            Order {
                quote_mint: 1u8.into(),
                base_mint: 3u8.into(),
                side: OrderSide::Sell,
                amount: 10,
                // No price limit by default
                worst_case_price: FixedPoint::from_integer(0),
                timestamp: TIMESTAMP,
            }
        ];
        pub static ref INITIAL_WALLET: SizedWallet = Wallet {
            balances: INITIAL_BALANCES.clone(),
            orders: INITIAL_ORDERS.clone(),
            keys: PUBLIC_KEYS.clone(),
            match_fee: FixedPoint::from_integer(0),
            managing_cluster: 0u8.into(),
            blinder: Scalar::from(42u64)
        };
    }

    // -------------
    // | Constants |
    // -------------

    /// The maximum number of balances allowed in a wallet for tests
    pub const MAX_BALANCES: usize = 2;
    /// The maximum number of orders allowed in a wallet for tests
    pub const MAX_ORDERS: usize = 2;
    /// The maximum number of fees allowed in a wallet for tests
    pub const MAX_FEES: usize = 1;
    /// The initial timestamp used in testing
    pub const TIMESTAMP: u64 = 3; // dummy value

    pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    pub type SizedWalletShare = WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------

    /// Construct secret shares of a wallet for testing
    pub fn create_wallet_shares<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> (
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        // Sample a random secret share for the blinder
        let mut rng = thread_rng();
        let blinder_share = Scalar::random(&mut rng);

        let blinder = wallet.blinder;
        create_wallet_shares_with_randomness(
            wallet,
            blinder,
            blinder_share,
            from_fn(|| Some(Scalar::random(&mut rng))),
        )
    }

    /// Create a multi-item opening in a Merkle tree, do so by constructing the
    /// Merkle tree from the given items, padded with zeros
    ///
    /// The return type is structured as a tuple with the following elements in
    /// order:
    ///     - root: The root of the Merkle tree
    ///     - openings: A vector of opening vectors; the sister nodes hashed
    ///       with the Merkle path
    ///     - opening_indices: A vector of opening index vectors; the left/right
    ///       booleans for the path
    pub fn create_multi_opening<const HEIGHT: usize>(
        items: &[Scalar],
    ) -> (Scalar, Vec<MerkleOpening<HEIGHT>>) {
        create_multi_opening_with_default_leaf(items, Scalar::zero() /* default_value */)
    }

    /// Create a multi opening with a non-zero default (empty) leaf value
    pub fn create_multi_opening_with_default_leaf<const HEIGHT: usize>(
        items: &[Scalar],
        default_leaf: Scalar,
    ) -> (Scalar, Vec<MerkleOpening<HEIGHT>>) {
        let tree_capacity = 2usize.pow(HEIGHT as u32);
        assert!(items.len() <= tree_capacity, "tree capacity exceeded by seed items");
        assert!(!items.is_empty(), "cannot create a multi-opening for an empty tree");

        let (root, mut opening_paths) =
            create_multi_opening_helper(items.to_vec(), default_leaf, HEIGHT);
        opening_paths.truncate(items.len());

        // Create Merkle opening paths from each of the results
        let merkle_paths = opening_paths
            .into_iter()
            .enumerate()
            .map(|(i, path)| (get_opening_indices(i, HEIGHT), path))
            .map(|(indices, path)| MerkleOpening {
                indices: indices.try_into().unwrap(),
                elems: path.try_into().unwrap(),
            })
            .collect_vec();

        (root, merkle_paths)
    }

    /// A recursive helper to compute a multi-opening for a set of leaves
    ///
    /// Returns the root and a set of paths, where path[i] is hte path for
    /// leaves[i]
    fn create_multi_opening_helper(
        mut leaves: Vec<Scalar>,
        zero_value: Scalar,
        height: usize,
    ) -> (Scalar, Vec<Vec<Scalar>>) {
        // If the height is zero we are at the root of the tree, return
        if height == 0 {
            return (leaves[0], vec![Vec::new()]);
        }

        // Otherwise, pad the leaves with zeros to an even number and fold into the next
        // recursive level
        let pad_length = leaves.len() % 2;
        leaves.append(&mut vec![zero_value; pad_length]);
        let next_level_leaves = leaves.chunks_exact(2).map(compute_poseidon_hash).collect_vec();

        // Recurse up the tree
        let zero_value = compute_poseidon_hash(&[zero_value, zero_value]);
        let (root, parent_openings) =
            create_multi_opening_helper(next_level_leaves, zero_value, height - 1);

        // Append sister nodes to each recursive result
        let mut openings: Vec<Vec<Scalar>> = Vec::with_capacity(leaves.len());
        for (leaf_chunk, recursive_opening) in leaves.chunks_exact(2).zip(parent_openings) {
            // Add the leaves to each other's paths
            let (left, right) = (leaf_chunk[0], leaf_chunk[1]);
            openings.push([vec![right], recursive_opening.clone()].concat());
            openings.push([vec![left], recursive_opening].concat());
        }

        (root, openings)
    }

    /// Get the opening indices for a given insertion index into a Merkle tree
    ///
    /// Here, the indices are represented as `Scalar` values where `0`
    /// represents a left child and `1` represents a right child
    fn get_opening_indices(leaf_index: usize, height: usize) -> Vec<bool> {
        let mut leaf_index = leaf_index as u64;
        let mut indices = Vec::with_capacity(height);

        for _ in 0..height {
            indices.push(leaf_index % 2 == 1);
            leaf_index >>= 1;
        }
        indices
    }

    // ---------------------
    // | Helper Validation |
    // ---------------------

    /// Test the Merkle tree root
    #[test]
    fn test_multi_opening_root() {
        const HEIGHT: usize = 2; // capacity 4 merkle tree
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let (root, _) = create_multi_opening::<HEIGHT>(&leaves);

        // Compute the expected root
        let expected_root = compute_poseidon_hash(&[
            compute_poseidon_hash(&[Scalar::from(1u64), Scalar::from(2u64)]),
            compute_poseidon_hash(&[Scalar::from(3u64), Scalar::zero()]),
        ]);

        assert_eq!(root, expected_root);
    }

    /// Test the Merkle tree opening
    #[test]
    fn test_multi_opening_path() {
        const HEIGHT: usize = 3; // capacity 8 merkle tree
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let (_, openings) = create_multi_opening::<HEIGHT>(&leaves);

        // Compute the expected opening for the first element
        let hash_3_and_0 = compute_poseidon_hash(&[Scalar::from(3u64), Scalar::zero()]);
        let hash_0_and_0 = compute_poseidon_hash(&[Scalar::zero(), Scalar::zero()]);
        let hash_0_four_times = compute_poseidon_hash(&[hash_0_and_0, hash_0_and_0]);

        // The expected opening for the first element
        let expected_first_opening = vec![Scalar::from(2u64), hash_3_and_0, hash_0_four_times];
        assert_eq!(openings[0].elems.to_vec(), expected_first_opening);

        let expected_second_opening = vec![Scalar::from(1u64), hash_3_and_0, hash_0_four_times];
        assert_eq!(openings[1].elems.to_vec(), expected_second_opening);
    }

    /// Test the path indices of the Merkle opening
    #[test]
    fn test_multi_opening_indices() {
        const HEIGHT: usize = 3; // capacity 8 merkle tree
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let (_, openings) = create_multi_opening::<HEIGHT>(&leaves);

        // Check the indices
        let expected_first_indices = vec![false, false, false];
        assert_eq!(openings[0].indices.to_vec(), expected_first_indices);

        let expected_second_indices = vec![true, false, false];
        assert_eq!(openings[1].indices.to_vec(), expected_second_indices);

        let expected_third_indices = vec![false, true, false];
        assert_eq!(openings[2].indices.to_vec(), expected_third_indices);
    }

    /// Verify that the wallet shares helper correctly splits and recombines
    #[test]
    fn test_split_wallet_into_shares() {
        // Split into secret shares
        let wallet = INITIAL_WALLET.clone();
        let wallet_blinder = wallet.blinder;
        let (private_share, public_share) = create_wallet_shares(&wallet);

        // Unblind the public shares, recover from shares
        let unblinded_public_shares = public_share.unblind_shares(wallet_blinder);
        let recovered_wallet = private_share + unblinded_public_shares;

        assert_eq!(wallet, recovered_wallet);
    }

    /// Verify that reblinding a wallet creates valid secret shares of the
    /// underlying wallet
    #[test]
    fn test_reblind_wallet() {
        use circuit_types::native_helpers::reblind_wallet;

        let mut wallet = INITIAL_WALLET.clone();
        let (private_share, _) = create_wallet_shares(&wallet);

        // Reblind the shares
        let (reblinded_private_shares, reblinded_public_shares) =
            reblind_wallet(&private_share, &wallet);

        // Unblind the public shares, recover from shares
        let recovered_blinder = reblinded_public_shares.blinder + reblinded_private_shares.blinder;
        let unblinded_public_shares = reblinded_public_shares.unblind_shares(recovered_blinder);
        let recovered_wallet = reblinded_private_shares + unblinded_public_shares;

        wallet.blinder = recovered_blinder;
        assert_eq!(wallet, recovered_wallet);
    }
}
