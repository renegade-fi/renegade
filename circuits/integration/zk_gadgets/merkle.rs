//! Groups integration tests for Merkle proofs

use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter},
    CRHScheme, MerkleTree,
};
use circuits::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    zk_gadgets::merkle::{
        MerkleStatement, MultiproverMerkleWitness, MultiproverPoseidonMerkleGadget,
    },
};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use itertools::Itertools;
use rand::{thread_rng, Rng};
use rand_core::OsRng;

use crate::{
    mpc_gadgets::{
        poseidon::convert_params, prime_field_to_scalar, scalar_to_prime_field, TestField,
    },
    zk_gadgets::multiprover_prove_and_verify,
    IntegrationTestArgs, TestWrapper,
};

/// The Merkle hash config for the specific instance of the Merkle hasher
struct MerkleConfig {}
impl Config for MerkleConfig {
    type Leaf = [TestField];
    type LeafDigest = TestField;
    type InnerDigest = TestField;

    type LeafHash = CRH<TestField>;
    type TwoToOneHash = TwoToOneCRH<TestField>;
    type LeafInnerDigestConverter = IdentityDigestConverter<TestField>;
}

/// Create a list of random field elements
fn random_field_elements(num_elements: usize) -> Vec<TestField> {
    let mut rng = OsRng {};
    (0..num_elements)
        .map(|_| scalar_to_prime_field(&Scalar::random(&mut rng)))
        .collect_vec()
}

/// Get the opening indices from the index, this can be done by bit-decomposing the input to
/// determine incrementally which subtree a given index should be a part of.
///
/// The tree indices from leaf to root are exactly the LSB decomposition of the scalar
fn get_opening_indices(leaf_index: usize, tree_height: usize) -> Vec<Scalar> {
    if tree_height == 0 {
        vec![]
    } else {
        let mut recursive_result = get_opening_indices(leaf_index >> 1, tree_height - 1);
        recursive_result.insert(0, Scalar::from((leaf_index % 2) as u64));
        recursive_result
    }
}

/// Tests a correct witness Merkle proof
#[allow(non_upper_case_globals)]
fn test_multiprover_merkle(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // A random input at the leaf
    const leaf_size: usize = 6;
    let num_leaves = 32;
    let tree_height = 10;

    // Build a random Merkle tree via arkworks
    let poseidon_config = PoseidonSpongeParameters::default();
    let arkworks_params = convert_params(&poseidon_config);

    let mut merkle_tree =
        MerkleTree::<MerkleConfig>::blank(&arkworks_params, &arkworks_params, tree_height).unwrap();

    let mut ark_leaf_data = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let leaf_data: [TestField; leaf_size] =
            (*random_field_elements(leaf_size)).try_into().unwrap();
        merkle_tree.update(i, &leaf_data).unwrap();
        ark_leaf_data.push(leaf_data);
    }

    // Party 0 uses their Merkle tree and shares the values to create the proof
    // Share the root
    let shared_root = test_args
        .borrow_fabric()
        .allocate_private_scalar(
            0, /* owning_party */
            prime_field_to_scalar(&merkle_tree.root()),
        )
        .map_err(|err| format!("Error sharing root: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening root: {:?}", err))?;

    // Share the opening for a random index
    let random_index = thread_rng().gen_range(0..num_leaves);
    let opening = merkle_tree.generate_proof(random_index).unwrap();
    let mut opening_scalars = opening
        .auth_path
        .iter()
        .rev() // Path comes in reverse
        .map(prime_field_to_scalar)
        .collect_vec();

    // Hash the sister leaf of the given scalar
    let sister_leaf_data = if random_index % 2 == 0 {
        ark_leaf_data[random_index + 1]
    } else {
        ark_leaf_data[random_index - 1]
    };
    let sister_leaf_hash: TestField = CRH::evaluate(&arkworks_params, sister_leaf_data).unwrap();

    opening_scalars.insert(0, prime_field_to_scalar(&sister_leaf_hash));
    let opening_indices = get_opening_indices(random_index, tree_height - 1);

    // Share the opening proof and the indices
    let shared_opening = test_args
        .borrow_fabric()
        .batch_allocate_private_scalars(0 /* owning_party */, &opening_scalars)
        .map_err(|err| format!("Error sharing opening: {:?}", err))?;
    let shared_indices = test_args
        .borrow_fabric()
        .batch_allocate_private_scalars(0 /* owning_party */, &opening_indices)
        .map_err(|err| format!("Error sharing indices: {:?}", err))?;
    let shared_leaf_data = test_args
        .borrow_fabric()
        .batch_allocate_private_scalars(
            0, /* owning_party */
            &ark_leaf_data[random_index]
                .iter()
                .map(prime_field_to_scalar)
                .collect_vec(),
        )
        .map_err(|err| format!("Error sharing leaf data: {:?}", err))?;

    // Build a witness
    let witness = MultiproverMerkleWitness {
        opening: shared_opening,
        opening_indices: shared_indices,
        leaf_data: shared_leaf_data,
    };

    let statement = MerkleStatement {
        expected_root: shared_root.to_scalar(),
        tree_height,
    };

    multiprover_prove_and_verify::<'_, _, _, MultiproverPoseidonMerkleGadget<'_, _, _>>(
        witness,
        statement,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error proving and verifying: {:?}", err))
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::merkle::test_multiprover_merkle",
    test_fn: test_multiprover_merkle
}));
