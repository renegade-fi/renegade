//! Groups circuitry for full zero knowledge circuits that we are interested
//! in proving knowledge of witness for throughout the network
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

// pub mod commitment_links;
pub mod valid_commitments;
// pub mod valid_match_mpc;
pub mod valid_reblind;
// pub mod valid_settle;
pub mod valid_wallet_create;
pub mod valid_wallet_update;

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use std::iter::from_fn;

    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use circuit_types::{
        balance::Balance,
        fee::Fee,
        fixed_point::FixedPoint,
        keychain::{PublicKeyChain, PublicSigningKey, NUM_KEYS},
        merkle::MerkleOpening,
        order::{Order, OrderSide},
        wallet::{Wallet, WalletShare},
    };
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use mpc_stark::algebra::scalar::Scalar;
    use num_bigint::BigUint;
    use rand::{thread_rng, CryptoRng, RngCore};
    use renegade_crypto::hash::{compute_poseidon_hash, default_poseidon_params};

    use circuit_types::native_helpers::create_wallet_shares_with_randomness;

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        // The key data for the wallet, note that only the identification keys are currently
        // computed correctly
        pub static ref PRIVATE_KEYS: Vec<Scalar> = vec![Scalar::one(); NUM_KEYS];
        pub static ref PUBLIC_KEYS: PublicKeyChain = PublicKeyChain {
            pk_root: PublicSigningKey::from(&BigUint::from(2u8).pow(256)),
            pk_match: compute_poseidon_hash(&[PRIVATE_KEYS[1]]).into(),
        };
        pub static ref INITIAL_BALANCES: [Balance; MAX_BALANCES] = [
            Balance { mint: 1u8.into(), amount: 5 },
            Balance {
                mint: 2u8.into(),
                amount: 10
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
        pub static ref INITIAL_FEES: [Fee; MAX_FEES] = [Fee {
            settle_key: BigUint::from(11u8),
            gas_addr: BigUint::from(1u8),
            percentage_fee: FixedPoint::from(0.01),
            gas_token_amount: 3,
        }];
        pub static ref INITIAL_WALLET: SizedWallet = Wallet {
            balances: INITIAL_BALANCES.clone(),
            orders: INITIAL_ORDERS.clone(),
            fees: INITIAL_FEES.clone(),
            keys: PUBLIC_KEYS.clone(),
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
        wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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

    /// Create a multi-item opening in a Merkle tree, do so by constructing the Merkle tree
    /// from the given items, padded with zeros
    ///
    /// The return type is structured as a tuple with the following elements in order:
    ///     - root: The root of the Merkle tree
    ///     - openings: A vector of opening vectors; the sister nodes hashed with the Merkle path
    ///     - opening_indices: A vector of opening index vectors; the left/right booleans for the path
    pub fn create_multi_opening<R: RngCore + CryptoRng, const HEIGHT: usize>(
        items: &[Scalar],
        rng: &mut R,
    ) -> (Scalar, Vec<MerkleOpening<HEIGHT>>) {
        let tree_capacity = 2usize.pow(HEIGHT as u32);
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
                .into_iter()
                .map(|s| s.inner())
                .chunks(2 /* size */)
                .into_iter()
            {
                let mut sponge = PoseidonSponge::new(&default_poseidon_params());
                sponge.absorb(&left_right.collect_vec());

                let squeezed: Scalar::Field =
                    sponge.squeeze_field_elements(1 /* num_elements */)[0];
                next_internal_nodes.push(Scalar::from(squeezed));
            }

            // Update the curr_indices vector to be the index of the parent node in the Merkle tree height
            // above the current height. This is simply \floor(index / 2)
            curr_indices = curr_indices.iter().map(|index| index >> 2).collect_vec();
            curr_internal_nodes = next_internal_nodes;
        }

        let merkle_root = curr_internal_nodes[0];

        // Reformat the openings and indices into the `MerkleOpening` type
        let merkle_openings = openings
            .into_iter()
            .zip(opening_indices.into_iter())
            .map(|(elems, indices)| MerkleOpening {
                elems: elems.try_into().unwrap(),
                indices: indices.try_into().unwrap(),
            })
            .collect_vec();
        (merkle_root, merkle_openings)
    }

    // ---------------------
    // | Helper Validation |
    // ---------------------

    /// Verify that the wallet shares helper correctly splits and recombines
    #[test]
    fn test_split_wallet_into_shares() {
        // Split into secret shares
        let wallet = INITIAL_WALLET.clone();
        let wallet_blinder = wallet.blinder;
        let (private_share, public_share) = create_wallet_shares(wallet.clone());

        // Unblind the public shares, recover from shares
        let unblinded_public_shares = public_share.unblind_shares(wallet_blinder);
        let recovered_wallet = private_share + unblinded_public_shares;

        assert_eq!(wallet, recovered_wallet);
    }

    /// Verify that reblinding a wallet creates valid secret shares of the underlying wallet
    #[test]
    fn test_reblind_wallet() {
        use circuit_types::native_helpers::reblind_wallet;

        let mut wallet = INITIAL_WALLET.clone();
        let (private_share, _) = create_wallet_shares(wallet.clone());

        // Reblind the shares
        let (reblinded_private_shares, reblinded_public_shares) =
            reblind_wallet(private_share, wallet.clone());

        // Unblind the public shares, recover from shares
        let recovered_blinder = reblinded_public_shares.blinder + reblinded_private_shares.blinder;
        let unblinded_public_shares = reblinded_public_shares.unblind_shares(recovered_blinder);
        let recovered_wallet = reblinded_private_shares + unblinded_public_shares;

        wallet.blinder = recovered_blinder;
        assert_eq!(wallet, recovered_wallet);
    }
}
