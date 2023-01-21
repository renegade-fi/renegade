//! Groups gadgets around computing Merkle entries and proving Merkle openings

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable, R1CSError,
        SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use rand_core::OsRng;
use std::{marker::PhantomData, ops::Neg};

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    MultiProverCircuit, SingleProverCircuit,
};

use super::poseidon::{MultiproverPoseidonHashGadget, PoseidonHashGadget};

/// The single-prover hash gadget, computes the Merkle root of a leaf given a path
/// of sister nodes
pub struct PoseidonMerkleHashGadget {}

impl PoseidonMerkleHashGadget {
    /// Compute the root of the tree given the leaf node and the path of
    /// sister nodes leading to the root
    pub fn compute_root<L, CS>(
        leaf_node: Vec<L>,
        opening: Vec<Variable>,
        opening_indices: Vec<Variable>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        assert_eq!(opening.len(), opening_indices.len());

        // Hash the leaf_node into a field element
        let leaf_hash: LinearCombination = Self::leaf_hash(&leaf_node, cs)?;
        Self::compute_root_prehashed(leaf_hash, opening, opening_indices, cs)
    }

    /// Compute the root given an already hashed leaf, i.e. do not hash a leaf buffer first
    pub fn compute_root_prehashed<S, CS>(
        leaf_node: S,
        opening: Vec<Variable>,
        opening_indices: Vec<Variable>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        S: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Hash the leaf_node into a field element
        let mut current_hash: LinearCombination = leaf_node.into();
        for (path_elem, lr_select) in opening.into_iter().zip(opening_indices.into_iter()) {
            // Select the left and right hand sides based on whether this node in the opening represents the
            // left or right hand child of its parent
            let (lhs, rhs) = Self::select_left_right(
                current_hash.clone(),
                path_elem.into(),
                lr_select.into(),
                cs,
            );
            current_hash = Self::hash_internal_nodes(&lhs, &rhs, cs)?;
        }

        Ok(current_hash)
    }

    /// Compute the root and constrain it to an expected value
    pub fn compute_and_constrain_root<L, CS>(
        leaf_node: Vec<L>,
        opening: Vec<Variable>,
        opening_indices: Vec<Variable>,
        expected_root: L,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        let root = Self::compute_root(leaf_node, opening, opening_indices, cs)?;
        cs.constrain(expected_root.into() - root);

        Ok(())
    }

    /// Compute the root from a prehashed leaf and constrain it to an expected value
    pub fn compute_and_constrain_root_prehashed<L, CS>(
        leaf_node: L,
        opening: Vec<Variable>,
        opening_indices: Vec<Variable>,
        expected_root: L,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        let root = Self::compute_root_prehashed(leaf_node, opening, opening_indices, cs)?;
        cs.constrain(expected_root.into() - root);

        Ok(())
    }

    /// Selects whether to place the current hash on the left or right hand
    /// side of the 2-1 hash.
    ///
    /// This is based on whether the current hash represents the left or right
    /// child of its parent to be computed
    fn select_left_right<L, CS>(
        current_hash: L,
        sister_node: L,
        lr_select: L,
        cs: &mut CS,
    ) -> (LinearCombination, LinearCombination)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let current_hash_lc = current_hash.into();
        let sister_node_lc = sister_node.into();
        let lr_select_lc = lr_select.into();

        // If lr_select == 0 { current_hash } else { sister_node }
        //      ==> current_hash * (1 - lr_select) + sister_node * lr_select
        let (_, _, left_child_term1) = cs.multiply(
            current_hash_lc.clone(),
            lr_select_lc.clone().neg() + Scalar::one(),
        );
        let (_, _, left_child_term2) = cs.multiply(sister_node_lc.clone(), lr_select_lc);

        let left_child = left_child_term1 + left_child_term2;

        // If lr_select == 0 { sister_node } else { current_hash }
        // We can avoid an extra multiplication here, because we know the lhs term, the rhs term is
        // equal to the other term, which can be computed by addition alone
        //      rhs = a + b - lhs
        let right_child = current_hash_lc + sister_node_lc - left_child.clone();
        (left_child, right_child)
    }

    /// Hash the value at the leaf into a bulletproof constraint value
    fn leaf_hash<L, CS>(values: &[L], cs: &mut CS) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Build a sponge hasher
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);
        hasher.batch_absorb(values, cs)?;

        hasher.squeeze(cs)
    }

    /// Hash two internal nodes in the (binary) Merkle tree, giving the tree value at
    /// the parent node
    fn hash_internal_nodes<CS: RandomizableConstraintSystem>(
        left: &LinearCombination,
        right: &LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);
        hasher.batch_absorb(&[left.clone(), right.clone()], cs)?;

        hasher.squeeze(cs)
    }
}

/// The witness to the statement defined by the Merkle gadget; that is one of
/// Merkle inclusion
#[derive(Clone, Debug)]
pub struct MerkleWitness {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    pub opening: Vec<Scalar>,
    /// The opening indices from the leaf node to the root, each value is zero or
    /// one: 0 indicating that the node in the opening at index i is a left hand
    /// child of its parent, 1 indicating it's a right hand child
    pub opening_indices: Vec<Scalar>,
    /// The preimage for the leaf i.e. the value that is sponge hashed into the leaf
    pub leaf_data: Vec<Scalar>,
}

/// The statement parameterization of the Merkle inclusion proof of knowledge
#[derive(Clone, Debug)]
pub struct MerkleStatement {
    /// The expected value of the root after hashing from the leaf
    pub expected_root: Scalar,
    /// The tree height, used to partition the commitments when given
    /// to the verifier as a vector
    pub tree_height: usize,
}

impl SingleProverCircuit for PoseidonMerkleHashGadget {
    type Statement = MerkleStatement;
    type Witness = MerkleWitness;
    type WitnessCommitment = Vec<CompressedRistretto>;

    const BP_GENS_CAPACITY: usize = 8192;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Vec<CompressedRistretto>, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let leaf_data_length = witness.leaf_data.len();
        let opening_len = witness.opening.len();

        let (opening_comm, opening_vars): (Vec<CompressedRistretto>, Vec<Variable>) = witness
            .opening
            .into_iter()
            .zip((0..opening_len).map(|_| Scalar::random(&mut rng)))
            .map(|(val, blind)| prover.commit(val, blind))
            .unzip();
        let (indices_comm, indices_vars): (Vec<CompressedRistretto>, Vec<Variable>) = witness
            .opening_indices
            .into_iter()
            .zip((0..opening_len).map(|_| Scalar::random(&mut rng)))
            .map(|(val, blind)| prover.commit(val, blind))
            .unzip();
        let (leaf_comm, leaf_vars): (Vec<CompressedRistretto>, Vec<Variable>) = witness
            .leaf_data
            .into_iter()
            .zip((0..leaf_data_length).map(|_| Scalar::random(&mut rng)))
            .map(|(val, blinder)| prover.commit(val, blinder))
            .unzip();

        // Commit to the expected root
        let root_var = prover.commit_public(statement.expected_root);

        // Apply the constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            leaf_vars,
            opening_vars,
            indices_vars,
            root_var,
            &mut prover,
        )
        .map_err(ProverError::R1CS)?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((
            opening_comm
                .into_iter()
                .chain(indices_comm.into_iter())
                .chain(leaf_comm.into_iter())
                .collect_vec(),
            proof,
        ))
    }

    fn verify(
        witness_commitments: Vec<CompressedRistretto>,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness
        // The first <tree-height> vars are the opening
        let opening_len = statement.tree_height - 1;
        let opening_vars = witness_commitments[..opening_len]
            .iter()
            .map(|comm| verifier.commit(*comm))
            .collect_vec();
        // The second <tree-height> vars are the opening indices
        let indices_vars = witness_commitments[opening_len..2 * opening_len]
            .iter()
            .map(|comm| verifier.commit(*comm))
            .collect_vec();
        assert_eq!(opening_vars.len(), indices_vars.len());

        // All remaining vars are the leaf payload
        let leaf_vars = witness_commitments[2 * opening_len..]
            .iter()
            .map(|comm| verifier.commit(*comm))
            .collect_vec();

        let root_var = verifier.commit_public(statement.expected_root);

        // Apply constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            leaf_vars,
            opening_vars,
            indices_vars,
            root_var,
            &mut verifier,
        )
        .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

/// Mulitprover gadget for Merkle proofs inside of a collaborative Bulletproof
pub struct MultiproverPoseidonMerkleGadget<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Phantom
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    MultiproverPoseidonMerkleGadget<'a, N, S>
{
    /// Compute the root of the tree given the leaf node and the path of
    /// sister nodes leading to the root
    pub fn compute_root<L, CS>(
        leaf_node: Vec<L>,
        opening: Vec<MpcVariable<N, S>>,
        opening_indices: Vec<MpcVariable<N, S>>,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        assert_eq!(opening.len(), opening_indices.len());

        // Hash the leaf_node into a field element
        let mut current_hash = Self::leaf_hash(&leaf_node, fabric.clone(), cs)?;
        for (path_elem, lr_select) in opening.into_iter().zip(opening_indices.into_iter()) {
            // Select the left and right hand sides based on whether this node in the opening represents the
            // left or right hand child of its parent
            let (lhs, rhs) = Self::select_left_right(
                current_hash.clone(),
                path_elem.into(),
                lr_select.into(),
                fabric.clone(),
                cs,
            )?;
            current_hash = Self::hash_internal_nodes(&lhs, &rhs, fabric.clone(), cs)?;
        }

        Ok(current_hash)
    }

    /// Selects whether to place the current hash on the left or right hand
    /// side of the 2-1 hash.
    ///
    /// This is based on whether the current hash represents the left or right
    /// child of its parent to be computed
    #[allow(clippy::type_complexity)]
    fn select_left_right<L, CS>(
        current_hash: L,
        sister_node: L,
        lr_select: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<(MpcLinearCombination<N, S>, MpcLinearCombination<N, S>), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        let current_hash_lc = current_hash.into();
        let sister_node_lc = sister_node.into();
        let lr_select_lc = lr_select.into();

        // If lr_select == 0 { current_hash } else { sister_node }
        //      ==> current_hash * (1 - lr_select) + sister_node * lr_select
        let (_, _, left_child_term1) = cs
            .multiply(
                &current_hash_lc,
                &(lr_select_lc.clone().neg()
                    + MpcLinearCombination::from_scalar(Scalar::one(), fabric.0)),
            )
            .map_err(ProverError::Collaborative)?;
        let (_, _, left_child_term2) = cs
            .multiply(&sister_node_lc, &lr_select_lc)
            .map_err(ProverError::Collaborative)?;

        let left_child = left_child_term1 + left_child_term2;

        // If lr_select == 0 { sister_node } else { current_hash }
        // We can avoid an extra multiplication here, because we know the lhs term, the rhs term is
        // equal to the other term, which can be computed by addition alone
        //      rhs = a + b - lhs
        let right_child = current_hash_lc + sister_node_lc - left_child.clone();
        Ok((left_child, right_child))
    }

    /// Compute the root and constrain it to an expected value
    pub fn compute_and_constrain_root<L, CS>(
        leaf_node: Vec<L>,
        opening: Vec<MpcVariable<N, S>>,
        opening_indices: Vec<MpcVariable<N, S>>,
        expected_root: L,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<(), ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
        L: Into<MpcLinearCombination<N, S>> + Clone,
    {
        let root = Self::compute_root(leaf_node, opening, opening_indices, fabric, cs)?;
        cs.constrain(expected_root.into() - root);

        Ok(())
    }

    /// Hash the value at the leaf into a bulletproof constraint value
    fn leaf_hash<L, CS>(
        values: &[L],
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination<N, S>, ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Build a sponge hasher
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = MultiproverPoseidonHashGadget::new(hasher_params, fabric);
        hasher.batch_absorb(values, cs)?;

        hasher.squeeze(cs)
    }

    /// Hash two internal nodes in the (binary) Merkle tree, giving the tree value at
    /// the parent node
    fn hash_internal_nodes<CS: MpcRandomizableConstraintSystem<'a, N, S>>(
        left: &MpcLinearCombination<N, S>,
        right: &MpcLinearCombination<N, S>,
        fabric: SharedFabric<N, S>,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination<N, S>, ProverError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = MultiproverPoseidonHashGadget::new(hasher_params, fabric);
        hasher.batch_absorb(&[left.clone(), right.clone()], cs)?;

        hasher.squeeze(cs)
    }
}

/// The witness to the statement defined by the Merkle gadget; that is one of
/// Merkle inclusion
#[derive(Clone, Debug)]
pub struct MultiproverMerkleWitness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    pub opening: Vec<AuthenticatedScalar<N, S>>,
    /// The opening indices from the leaf node to the root, each value is zero or
    /// one: 0 indicating that the node in the opening at index i is a left hand
    /// child of its parent, 1 indicating it's a right hand child
    pub opening_indices: Vec<AuthenticatedScalar<N, S>>,
    /// The preimage for the leaf i.e. the value that is sponge hashed into the leaf
    pub leaf_data: Vec<AuthenticatedScalar<N, S>>,
}

impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiProverCircuit<'a, N, S>
    for MultiproverPoseidonMerkleGadget<'a, N, S>
{
    type Witness = MultiproverMerkleWitness<N, S>;
    type WitnessCommitment = Vec<AuthenticatedCompressedRistretto<N, S>>;
    type Statement = MerkleStatement;

    const BP_GENS_CAPACITY: usize = 8192;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<
        (
            Vec<AuthenticatedCompressedRistretto<N, S>>,
            SharedR1CSProof<N, S>,
        ),
        ProverError,
    > {
        assert_eq!(witness.opening.len(), witness.opening_indices.len());

        // Commit to the private variables all together to save communication
        let mut rng = OsRng {};
        let opening_length = witness.opening.len();
        let num_witness_commits = 2 * opening_length + witness.leaf_data.len();

        let (witness_comm, witness_vars) = prover
            .batch_commit_preshared(
                &witness
                    .opening
                    .into_iter()
                    .chain(witness.opening_indices.into_iter())
                    .chain(witness.leaf_data.into_iter())
                    .collect_vec(),
                &(0..num_witness_commits)
                    .map(|_| Scalar::random(&mut rng))
                    .collect_vec(),
            )
            .map_err(|err| ProverError::Mpc(MpcError::SharingError(err.to_string())))?;

        // Split commitments back into unchained variables
        let opening_vars = witness_vars[..opening_length].to_vec();
        let indices_vars = witness_vars[opening_length..2 * opening_length].to_vec();
        let leaf_data_vars = witness_vars[2 * opening_length..].to_vec();

        let (_, root_var) = prover.commit_public(statement.expected_root);

        // Apply the constraints
        Self::compute_and_constrain_root(
            leaf_data_vars,
            opening_vars,
            indices_vars,
            root_var,
            fabric,
            &mut prover,
        )?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitments: Vec<CompressedRistretto>,
        statement: Self::Statement,
        proof: R1CSProof,
        verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Forward to the single prover verifier
        PoseidonMerkleHashGadget::verify(witness_commitments, statement, proof, verifier)
    }
}

#[cfg(test)]
pub(crate) mod merkle_test {
    use ark_crypto_primitives::{
        crh::poseidon::{TwoToOneCRH, CRH},
        merkle_tree::{Config, IdentityDigestConverter},
        CRHScheme, MerkleTree,
    };
    use crypto::{
        fields::{prime_field_to_scalar, scalar_to_prime_field, DalekRistrettoField},
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use mpc_bulletproof::r1cs_mpc::R1CSError;
    use rand::{thread_rng, Rng};
    use rand_core::OsRng;

    use crate::{
        errors::VerifierError, test_helpers::bulletproof_prove_and_verify,
        zk_gadgets::merkle::PoseidonMerkleHashGadget,
    };

    use super::{MerkleStatement, MerkleWitness};

    struct MerkleConfig {}
    impl Config for MerkleConfig {
        type Leaf = [DalekRistrettoField];
        type LeafDigest = DalekRistrettoField;
        type InnerDigest = DalekRistrettoField;

        type LeafHash = CRH<DalekRistrettoField>;
        type TwoToOneHash = TwoToOneCRH<DalekRistrettoField>;
        type LeafInnerDigestConverter = IdentityDigestConverter<DalekRistrettoField>;
    }

    /// Create a random sequence of field elements
    fn random_field_elements(n: usize) -> Vec<DalekRistrettoField> {
        let mut rng = OsRng {};
        (0..n)
            .map(|_| scalar_to_prime_field(&Scalar::random(&mut rng)))
            .collect_vec()
    }

    /// Get the opening indices from the index, this can be done by bit-decomposing the input to
    /// determine incrementally which subtree a given index should be a part of.
    ///
    /// The tree indices from leaf to root are exactly the LSB decomposition of the scalar
    pub(crate) fn get_opening_indices(leaf_index: usize, tree_height: usize) -> Vec<Scalar> {
        if tree_height == 0 {
            vec![]
        } else {
            let mut recursive_result = get_opening_indices(leaf_index >> 1, tree_height - 1);
            recursive_result.insert(0, Scalar::from((leaf_index % 2) as u64));
            recursive_result
        }
    }

    #[test]
    #[allow(non_upper_case_globals)]
    fn test_against_arkworks() {
        // A random input at the leaf
        const leaf_size: usize = 6;
        let num_leaves = 32;
        let tree_height = 10;

        // Build a random Merkle tree via arkworks
        let arkworks_params = default_poseidon_params();

        let mut merkle_tree =
            MerkleTree::<MerkleConfig>::blank(&arkworks_params, &arkworks_params, tree_height)
                .unwrap();

        let mut ark_leaf_data = Vec::with_capacity(num_leaves);
        for i in 0..num_leaves {
            let leaf_data: [DalekRistrettoField; leaf_size] =
                (*random_field_elements(leaf_size)).try_into().unwrap();
            merkle_tree.update(i, &leaf_data).unwrap();
            ark_leaf_data.push(leaf_data);
        }

        // Generate a proof for a random index and prove it in the native gadget
        let random_index = thread_rng().gen_range(0..num_leaves);
        let expected_root = prime_field_to_scalar(&merkle_tree.root());
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
        let sister_leaf_hash: DalekRistrettoField =
            CRH::evaluate(&arkworks_params, sister_leaf_data).unwrap();

        opening_scalars.insert(0, prime_field_to_scalar(&sister_leaf_hash));

        // Convert the leaf data for the given leaf to scalars
        let leaf_data = ark_leaf_data[random_index]
            .iter()
            .map(prime_field_to_scalar)
            .collect_vec();

        // Prove and verify the statement
        let witness = MerkleWitness {
            leaf_data,
            opening: opening_scalars,
            opening_indices: get_opening_indices(random_index, opening.auth_path.len() + 1),
        };

        let statement = MerkleStatement {
            expected_root,
            tree_height,
        };

        bulletproof_prove_and_verify::<PoseidonMerkleHashGadget>(witness, statement).unwrap();
    }

    #[test]
    fn test_invalid_witness() {
        // A random input at the leaf
        let mut rng = OsRng {};
        let n = 6;
        let tree_height = 10;
        let leaf_data = (0..n).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Compute the correct root via Arkworks
        let arkworks_params = default_poseidon_params();

        let arkworks_leaf_data = leaf_data.iter().map(scalar_to_prime_field).collect_vec();

        let mut merkle_tree =
            MerkleTree::<MerkleConfig>::blank(&arkworks_params, &arkworks_params, tree_height)
                .unwrap();

        merkle_tree
            .update(0 /* index */, &arkworks_leaf_data)
            .unwrap();

        // Random (incorrect) root
        let expected_root = Scalar::random(&mut rng);
        let opening = merkle_tree.generate_proof(0 /* index */).unwrap();
        let mut opening_scalars = opening
            .auth_path
            .iter()
            .rev() // Path comes in reverse
            .map(prime_field_to_scalar)
            .collect_vec();

        // Add a zero to the opening scalar for the next leaf
        opening_scalars.insert(0, Scalar::zero());

        // Prove and verify the statement
        let witness = MerkleWitness {
            leaf_data,
            opening: opening_scalars,
            opening_indices: (0..opening.auth_path.len() + 1)
                .map(|_| Scalar::zero())
                .collect_vec(),
        };

        let statement = MerkleStatement {
            expected_root,
            tree_height,
        };

        let res = bulletproof_prove_and_verify::<PoseidonMerkleHashGadget>(witness, statement);
        assert_eq!(res, Err(VerifierError::R1CS(R1CSError::VerificationError)));
    }
}
