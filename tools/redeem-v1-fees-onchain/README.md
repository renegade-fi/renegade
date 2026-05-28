# redeem-v1-fees-onchain

Headless redemption of v1 darkpool fees, for chains whose live v1 relayer has
been wound down. Lives inside the `renegade-v1` workspace so it can use the
crate-private types from `darkpool-client`, `circuits`, `common`, etc. in
later phases.

## Phases

| phase | subcommand          | status     | what it does                                              |
| ----- | ------------------- | ---------- | --------------------------------------------------------- |
| 0     | `inspect`           | **active** | DB-only listing of unredeemed fees + fee wallets          |
| 1     | `reconstruct-wallet`| planned    | walk a fee wallet's blinder stream on-chain               |
| 2     | `decrypt-note`      | planned    | fetch + decrypt a single fee note from its tx             |
| 3     | `prove-redeem`      | planned    | generate a `ValidFeeRedemption` proof, no submission      |
| 4     | `submit-redeem`     | planned    | submit one note redemption to the darkpool contract       |
| 5     | `submit-withdraw`   | planned    | withdraw fee-wallet balances to the FeeRedemption EOA     |

Every phase 4+ subcommand will be gated behind an explicit `--execute` flag.

## Build

Use a dedicated `CARGO_TARGET_DIR` so the build artifacts don't collide with
other renegade-v1 builds (the workspace is large; sharing `target/` between
tools triggers frequent rebuilds).

```bash
cd /home/di/renegade-fi/renegade-v1
CARGO_TARGET_DIR=/tmp/cargo-redeem-v1-fees-onchain CARGO_BUILD_JOBS=4 \
  cargo build --release -p redeem-v1-fees-onchain
# binary: /tmp/cargo-redeem-v1-fees-onchain/release/redeem-v1-fees-onchain
```

## Phase 0 — inspect

DB-only. Lists every unredeemed fee row and every fee-redemption wallet for
the selected chain. The DB stores `chain = 'arbitrum'` for both
arbitrum-one and arbitrum-sepolia (and `'base'` for base-mainnet /
base-sepolia); the env distinction comes from which DB you connect to.

Resolves `DATABASE_URL` from AWS Secrets Manager (default secret name
`/mainnet/funds-manager-db-url`) unless you pass `--database-url` or set
the env var. The DB is in the funds-manager VPC, so you need VPC reachability
(VPN / bastion / SSM port-forward).

```bash
# Make sure AWS creds are loaded into the env (handles `Login` profiles):
eval "$(aws configure export-credentials --profile renegade --format env)"
unset AWS_PROFILE

BIN=/tmp/cargo-redeem-v1-fees-onchain/release/redeem-v1-fees-onchain

# arbitrum-one
$BIN inspect --chain arbitrum-one

# base-mainnet
$BIN inspect --chain base-mainnet
```

Sample output sketch:

```
================================================================
redeem-v1-fees-onchain inspect
  chain (DB):      arbitrum
  chain (display): arbitrum-one
================================================================

unredeemed fees (147 rows):
  id   mint                                          amount(raw)  tx_hash         receiver
  ...
  ----

unredeemed fee totals by mint:
  mint                                          total(raw)  n_notes
  0xa0b86991...                                  23456789012  73
  0xfd086bc7...                                  1234567890   12
  ...

fee-redemption wallets (5 rows):
  wallet_id                              mints                            secret_id
  ...
```

The numbers should match what `GET /fees/arbitrum/get-unredeemed-fee-totals`
returns when the v1 funds-manager is up.

## What Phase 0 does not do

- No on-chain reads (so it doesn't matter whether the arb1 relayer or RPC
  is reachable from your laptop).
- No price/decimal conversion (`amount` is raw u128). For USD values, run
  `redeem-v1-fees inspect --chain arbitrum-one` (the other repo, which talks
  to a running funds-manager and applies token-mappings + price-reporter).
- No writes.

## Future phases at a glance

Each phase reuses the renegade-v1 primitives directly:

- **Phase 1** uses `darkpool-client::arbitrum::abi::*_SELECTOR` constants and
  the calldata decoders in `darkpool-client/src/arbitrum/helpers.rs` to walk
  the blinder stream forward from `derive_blinder_seed(eth_key)`, lifting
  the algorithm from `tools/reconstruct-v1-balances-onchain` but starting
  from genesis blinder (no MDBX snapshot dependency).
- **Phase 2** lifts `get_note_from_tx_with_key` from
  `relayer-extensions-v1/funds-manager/funds-manager-server/src/fee_indexer/
  index_fees.rs` to decrypt a single note given `(tx_hash, receiver_pubkey)`
  and the chain's `relayer_decryption_key`.
- **Phase 3** builds `SizedValidFeeRedemptionStatement` /
  `SizedValidFeeRedemptionWitness` (see
  `circuits/src/zk_circuits/valid_fee_redemption.rs`) from the reconstructed
  old wallet, the new wallet (= old + note), the note opening, and the
  recipient decryption key. Generates the proof via the single-prover API.
- **Phase 4** calls `darkpool_client::redeem_fee(proof, sig_bytes)` and
  watches for nullifier consumption (mirrors
  `task-driver::tasks::redeem_fee`).
- **Phase 5** repeats the dance for a `ValidWalletUpdate` proof and an
  `update_wallet` tx that moves balance into the FeeRedemption EOA.
