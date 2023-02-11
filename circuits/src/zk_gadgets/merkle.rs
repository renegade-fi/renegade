//! Groups gadgets around computing Merkle entries and proving Merkle openings

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::ops::Neg;

use crate::{
    errors::{ProverError, VerifierError},
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    CommitProver, CommitVerifier, SingleProverCircuit,
};

use super::poseidon::PoseidonHashGadget;

/// A type alias for readability
pub type MerkleRoot = Scalar;

/// The single-prover hash gadget, computes the Merkle root of a leaf given a path
/// of sister nodes
pub struct PoseidonMerkleHashGadget {}

impl PoseidonMerkleHashGadget {
    /// Compute the root of the tree given the leaf node and the path of
    /// sister nodes leading to the root
    pub fn compute_root<L, CS>(
        leaf_node: Vec<L>,
        opening: MerkleOpeningVar,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Hash the leaf_node into a field element
        let leaf_hash: LinearCombination = Self::leaf_hash(&leaf_node, cs)?;
        Self::compute_root_prehashed(leaf_hash, opening, cs)
    }

    /// Compute the root given an already hashed leaf, i.e. do not hash a leaf buffer first
    pub fn compute_root_prehashed<S, CS>(
        leaf_node: S,
        opening: MerkleOpeningVar,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        S: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Hash the leaf_node into a field element
        let mut current_hash: LinearCombination = leaf_node.into();
        for (path_elem, lr_select) in opening.elems.into_iter().zip(opening.indices.into_iter()) {
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
        opening: MerkleOpeningVar,
        expected_root: L,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        let root = Self::compute_root(leaf_node, opening, cs)?;
        cs.constrain(expected_root.into() - root);

        Ok(())
    }

    /// Compute the root from a prehashed leaf and constrain it to an expected value
    pub fn compute_and_constrain_root_prehashed<L, CS>(
        leaf_node: L,
        opening: MerkleOpeningVar,
        expected_root: L,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
        L: Into<LinearCombination> + Clone,
    {
        let root = Self::compute_root_prehashed(leaf_node, opening, cs)?;
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

/// A fully specified merkle opening from hashed leaf to root
#[derive(Clone, Debug)]
pub struct MerkleOpening {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    pub elems: Vec<Scalar>,
    /// The opening indices from the leaf node to the root, each value is zero or
    /// one: 0 indicating that the node in the opening at index i is a left hand
    /// child of its parent, 1 indicating it's a right hand child
    pub indices: Vec<Scalar>,
}

/// A Merkle opening that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct MerkleOpeningVar {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    pub elems: Vec<Variable>,
    /// The opening indices from the leaf node to the root, each value is zero or
    /// one: 0 indicating that the node in the opening at index i is a left hand
    /// child of its parent, 1 indicating it's a right hand child
    pub indices: Vec<Variable>,
}

/// A commitment to a Merkle opening in a constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleOpeningCommitment {
    /// The opening from the leaf node to the root, i.e. the set of sister nodes
    /// that hash together with the input from the leaf to the root
    pub elems: Vec<CompressedRistretto>,
    /// The opening indices from the leaf node to the root, each value is zero or
    /// one: 0 indicating that the node in the opening at index i is a left hand
    /// child of its parent, 1 indicating it's a right hand child
    pub indices: Vec<CompressedRistretto>,
}

impl CommitProver for MerkleOpening {
    type VarType = MerkleOpeningVar;
    type CommitType = MerkleOpeningCommitment;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (opening_comms, opening_vars): (Vec<CompressedRistretto>, Vec<Variable>) = self
            .elems
            .iter()
            .map(|opening| prover.commit(*opening, Scalar::random(rng)))
            .unzip();

        let (index_comms, index_vars): (Vec<CompressedRistretto>, Vec<Variable>) = self
            .indices
            .iter()
            .map(|index| prover.commit(*index, Scalar::random(rng)))
            .unzip();

        Ok((
            MerkleOpeningVar {
                elems: opening_vars,
                indices: index_vars,
            },
            MerkleOpeningCommitment {
                elems: opening_comms,
                indices: index_comms,
            },
        ))
    }
}

impl CommitVerifier for MerkleOpeningCommitment {
    type VarType = MerkleOpeningVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let elem_vars = self
            .elems
            .iter()
            .map(|elem| verifier.commit(*elem))
            .collect_vec();
        let index_vars = self
            .indices
            .iter()
            .map(|index| verifier.commit(*index))
            .collect_vec();

        Ok(MerkleOpeningVar {
            elems: elem_vars,
            indices: index_vars,
        })
    }
}

/// The witness to the statement defined by the Merkle gadget; that is one of
/// Merkle inclusion
#[derive(Clone, Debug)]
pub struct MerkleWitness {
    /// The opening of the leaf into the root
    opening: MerkleOpening,
    /// The preimage for the leaf i.e. the value that is sponge hashed into the leaf
    leaf_data: Vec<Scalar>,
}

/// A Merkle opening witness that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct MerkleWitnessVar {
    /// The opening of the leaf into the root
    opening: MerkleOpeningVar,
    /// The preimage for the leaf i.e. the value that is sponge hashed into the leaf
    leaf_data: Vec<Variable>,
}

/// A commitment to the witness type for a Merkle opening proof
#[derive(Clone, Debug)]
pub struct MerkleWitnessCommitment {
    /// The opening of the leaf into the root
    opening: MerkleOpeningCommitment,
    /// The preimage for the leaf i.e. the value that is sponge hashed into the leaf
    leaf_data: Vec<CompressedRistretto>,
}

impl CommitProver for MerkleWitness {
    type VarType = MerkleWitnessVar;
    type CommitType = MerkleWitnessCommitment;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (opening_var, opening_comm) = self.opening.commit_prover(rng, prover).unwrap();
        let (leaf_comms, leaf_vars): (Vec<CompressedRistretto>, Vec<Variable>) = self
            .leaf_data
            .iter()
            .map(|leaf| prover.commit(*leaf, Scalar::random(rng)))
            .unzip();

        Ok((
            MerkleWitnessVar {
                opening: opening_var,
                leaf_data: leaf_vars,
            },
            MerkleWitnessCommitment {
                opening: opening_comm,
                leaf_data: leaf_comms,
            },
        ))
    }
}

impl CommitVerifier for MerkleWitnessCommitment {
    type VarType = MerkleWitnessVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let opening_var = self.opening.commit_verifier(verifier).unwrap();
        let leaf_vars = self
            .leaf_data
            .iter()
            .map(|leaf| verifier.commit(*leaf))
            .collect_vec();

        Ok(MerkleWitnessVar {
            opening: opening_var,
            leaf_data: leaf_vars,
        })
    }
}

/// The statement parameterization of the Merkle inclusion proof of knowledge
#[derive(Clone, Debug)]
pub struct MerkleStatement {
    /// The expected value of the root after hashing from the leaf
    pub expected_root: MerkleRoot,
    /// The tree height, used to partition the commitments when given
    /// to the verifier as a vector
    pub tree_height: usize,
}

impl SingleProverCircuit for PoseidonMerkleHashGadget {
    type Statement = MerkleStatement;
    type Witness = MerkleWitness;
    type WitnessCommitment = MerkleWitnessCommitment;

    const BP_GENS_CAPACITY: usize = 8192;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

        // Commit to the expected root
        let root_var = prover.commit_public(statement.expected_root);

        // Apply the constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            witness_var.leaf_data,
            witness_var.opening,
            root_var,
            &mut prover,
        )
        .map_err(ProverError::R1CS)?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitments: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness and statement
        let witness_vars = witness_commitments.commit_verifier(&mut verifier).unwrap();
        let root_var = verifier.commit_public(statement.expected_root);

        // Apply constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            witness_vars.leaf_data,
            witness_vars.opening,
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
        errors::VerifierError,
        test_helpers::bulletproof_prove_and_verify,
        zk_gadgets::merkle::{MerkleOpening, PoseidonMerkleHashGadget},
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
            opening: MerkleOpening {
                elems: opening_scalars,
                indices: get_opening_indices(random_index, opening.auth_path.len() + 1),
            },
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
            opening: MerkleOpening {
                elems: opening_scalars,
                indices: (0..opening.auth_path.len() + 1)
                    .map(|_| Scalar::zero())
                    .collect_vec(),
            },
        };

        let statement = MerkleStatement {
            expected_root,
            tree_height,
        };

        let res = bulletproof_prove_and_verify::<PoseidonMerkleHashGadget>(witness, statement);
        assert_eq!(res, Err(VerifierError::R1CS(R1CSError::VerificationError)));
    }
}
