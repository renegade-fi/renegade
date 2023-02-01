//! Groups circuitry for full zero knowledge circuits that we are interested
//! in proving knowledge of witness for throughout the network
pub mod valid_commitments;
pub mod valid_match_encryption;
pub mod valid_match_mpc;
pub mod valid_settle;
pub mod valid_wallet_create;
pub mod valid_wallet_update;

#[cfg(test)]
mod test_helpers {
    use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            biguint_to_prime_field, prime_field_to_scalar, scalar_to_prime_field,
            DalekRistrettoField,
        },
        hash::default_poseidon_params,
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, RngCore};

    use crate::{
        types::{
            balance::Balance,
            fee::Fee,
            note::Note,
            order::{Order, OrderSide},
            wallet::{Wallet, NUM_KEYS},
        },
        zk_gadgets::{fixed_point::FixedPoint, merkle::merkle_test::get_opening_indices},
    };

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        pub(crate) static ref INITIAL_BALANCES: [Balance; MAX_BALANCES] = [
            Balance { mint: 1, amount: 5 },
            Balance {
                mint: 2,
                amount: 10
            }
        ];
        pub(crate) static ref INITIAL_ORDERS: [Order; MAX_ORDERS] = [
            Order {
                quote_mint: 1,
                base_mint: 2,
                side: OrderSide::Buy,
                price: FixedPoint::from(5.),
                amount: 1,
                timestamp: TIMESTAMP,
            },
            Order {
                quote_mint: 1,
                base_mint: 3,
                side: OrderSide::Sell,
                price: FixedPoint::from(2.),
                amount: 10,
                timestamp: TIMESTAMP,
            }
        ];
        pub(crate) static ref INITIAL_FEES: [Fee; MAX_FEES] = [Fee {
            settle_key: BigUint::from(11u8),
            gas_addr: BigUint::from(1u8),
            percentage_fee: FixedPoint::from(0.01),
            gas_token_amount: 3,
        }];
        pub(crate) static ref INITIAL_WALLET: SizedWallet = Wallet {
            balances: INITIAL_BALANCES.clone(),
            orders: INITIAL_ORDERS.clone(),
            fees: INITIAL_FEES.clone(),
            keys: vec![Scalar::from(1u64); NUM_KEYS].try_into().unwrap(),
            randomness: Scalar::from(42u64)
        };
    }

    // -------------
    // | Constants |
    // -------------

    /// The maximum number of balances allowed in a wallet for tests
    pub(crate) const MAX_BALANCES: usize = 2;
    /// The maximum number of orders allowed in a wallet for tests
    pub(crate) const MAX_ORDERS: usize = 2;
    /// The maximum number of fees allowed in a wallet for tests
    pub(crate) const MAX_FEES: usize = 1;
    /// The initial timestamp used in testing
    pub(crate) const TIMESTAMP: u64 = 3; // dummy value

    pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------
    /// Compute the commitment to a wallet
    pub(crate) fn compute_wallet_commitment(wallet: &SizedWallet) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());

        // Hash the balances into the state
        for balance in wallet.balances.iter() {
            hasher.absorb(&vec![balance.mint, balance.amount]);
        }

        // Hash the orders into the state
        for order in wallet.orders.iter() {
            hasher.absorb(&vec![
                order.quote_mint,
                order.base_mint,
                order.side as u64,
                order.price.to_owned().into(),
                order.amount,
            ]);
        }

        // Hash the fees into the state
        for fee in wallet.fees.iter() {
            hasher.absorb(&vec![
                biguint_to_prime_field(&fee.settle_key),
                biguint_to_prime_field(&fee.gas_addr),
            ]);

            hasher.absorb(&vec![fee.gas_token_amount, fee.percentage_fee.into()]);
        }

        // Hash the keys into the state
        hasher.absorb(&wallet.keys.iter().map(scalar_to_prime_field).collect_vec());

        // Hash the randomness into the state
        hasher.absorb(&scalar_to_prime_field(&wallet.randomness));

        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Compute the commitment to a note
    pub(crate) fn compute_note_commitment(note: &Note) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![
            note.mint1,
            note.volume1,
            note.direction1 as u64,
            note.mint2,
            note.volume2,
            note.direction2 as u64,
            note.fee_mint,
            note.fee_volume,
            note.fee_direction as u64,
            note.type_ as u64,
            note.randomness,
        ]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a wallet, create a dummy opening to a dummy root
    ///
    /// Returns a scalar and two vectors representing:
    ///     - The root of the Merkle tree
    ///     - The opening values (sister nodes)
    ///     - The opening indices (left or right)
    pub(crate) fn create_wallet_opening<R: RngCore + CryptoRng>(
        wallet: &SizedWallet,
        height: usize,
        index: usize,
        rng: &mut R,
    ) -> (Scalar, Vec<Scalar>, Vec<Scalar>) {
        // Create random sister nodes for the opening
        let random_opening = (0..height - 1).map(|_| Scalar::random(rng)).collect_vec();
        let opening_indices = get_opening_indices(index, height);

        // Compute the root of the mock Merkle tree
        let mut curr_root = compute_wallet_commitment(wallet);
        for (path_index, sister_node) in opening_indices.iter().zip(random_opening.iter()) {
            let mut sponge = PoseidonSponge::new(&default_poseidon_params());

            // Left hand child
            let left_right = if path_index.eq(&Scalar::zero()) {
                vec![curr_root, scalar_to_prime_field(sister_node)]
            } else {
                vec![scalar_to_prime_field(sister_node), curr_root]
            };

            sponge.absorb(&left_right);
            curr_root = sponge.squeeze_field_elements(1 /* num_elements */)[0];
        }

        (
            prime_field_to_scalar(&curr_root),
            random_opening,
            opening_indices,
        )
    }

    /// Create a multi-item opening in a Merkle tree, do so by constructing the Merkle tree
    /// from the given items, padded with zeros
    ///
    /// The return type is structured as a tuple with the following elements in order:
    ///     - root: The root of the Merkle tree
    ///     - openings: A vector of opening vectors; the sister nodes hashed with the Merkle path
    ///     - opening_indices: A vector of opening index vectors; the left/right booleans for the path
    pub(crate) fn create_multi_opening<R: RngCore + CryptoRng>(
        items: &[Scalar],
        height: usize,
        rng: &mut R,
    ) -> (Scalar, Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
        let tree_capacity = 2usize.pow(height as u32);
        assert!(
            items.len() < tree_capacity,
            "tree capacity exceeded by seed items"
        );

        // Pad the inputs up to the tree capacity
        let mut merkle_leaves = items.to_vec();
        merkle_leaves.append(&mut vec![Scalar::random(rng); tree_capacity - items.len()]);

        // The return variables
        let mut openings = vec![Vec::new(); items.len()];
        let mut opening_indices = vec![Vec::new(); items.len()];

        // Compute the openings and root of the tree
        let mut curr_internal_nodes = merkle_leaves.clone();
        let mut curr_indices = (0..items.len()).collect_vec();

        // Loop over the levels of the tree, construct the openings as we go
        while curr_internal_nodes.len() > 1 {
            // The curr_indices represents the indices of each opening's path in the current height
            // compute a sister node for each at the given height and add it to the opening for that
            // path.
            for (i, ind) in curr_indices.iter().enumerate() {
                // Compute the opening index (i.e. whether this is a left or right child)
                let path_index = ind % 2;
                // Compute the sister node for the given index at the given height
                let sister_node =
                    curr_internal_nodes[if path_index == 0 { ind + 1 } else { ind - 1 }];

                openings[i].push(sister_node);
                opening_indices[i].push(Scalar::from(path_index as u8));
            }

            // Hash together each left and right pair to get the internal node values at the next height
            let mut next_internal_nodes = Vec::with_capacity(curr_internal_nodes.len() / 2);
            for left_right in curr_internal_nodes
                .chunks(2 /* size */)
                .map(|chunk| chunk.iter().map(scalar_to_prime_field).collect_vec())
            {
                let mut sponge = PoseidonSponge::new(&default_poseidon_params());
                sponge.absorb(&left_right);

                let squeezed: DalekRistrettoField =
                    sponge.squeeze_field_elements(1 /* num_elements */)[0];
                next_internal_nodes.push(prime_field_to_scalar(&squeezed));
            }

            // Update the curr_indices vector to be the index of the parent node in the Merkle tree height
            // above the current height. This is simply \floor(index / 2)
            curr_indices = curr_indices.iter().map(|index| index >> 2).collect_vec();
            curr_internal_nodes = next_internal_nodes;
        }

        let merkle_root = curr_internal_nodes[0];
        (merkle_root, openings, opening_indices)
    }

    /// Given a wallet and its commitment, compute the wallet spend nullifier
    pub(crate) fn compute_wallet_spend_nullifier(
        wallet: &SizedWallet,
        commitment: DalekRistrettoField,
    ) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![commitment, scalar_to_prime_field(&wallet.randomness)]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a wallet and its commitment, compute the wallet match nullifier
    pub(crate) fn compute_wallet_match_nullifier(
        wallet: &SizedWallet,
        commitment: DalekRistrettoField,
    ) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![
            commitment,
            scalar_to_prime_field(&(wallet.randomness + Scalar::one())),
        ]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }

    /// Given a note and its commitment, compute the note redeem nullifier
    pub(crate) fn compute_note_redeem_nullifier(
        note_commitment: DalekRistrettoField,
        pk_settle_receiver: DalekRistrettoField,
    ) -> DalekRistrettoField {
        let mut hasher = PoseidonSponge::new(&default_poseidon_params());
        hasher.absorb(&vec![note_commitment, pk_settle_receiver]);
        hasher.squeeze_field_elements(1 /* num_elements */)[0]
    }
}
