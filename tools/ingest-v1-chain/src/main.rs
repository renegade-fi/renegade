//! ingest-v1-chain — phase 1 of the refactored v1-refund pipeline.
//!
//! One RPC pass over the v1 darkpool proxy `[DEPLOY_BLOCK, ATTACK_BLOCK]`.
//! Produces three append-only JSONL files in `--out-dir`:
//!
//!   external-transfers.jsonl  — every `ExternalTransfer` event from the
//!     proxy, one row per log.
//!   wallet-updated.jsonl      — every `WalletUpdated(uint256)` event from
//!     the proxy, one row per log.
//!   update-wallet-txs.jsonl   — for every unique `tx_hash` referenced
//!     above, fetched once via `eth_getTransactionByHash`. When the
//!     top-level selector is `updateWallet`, we additionally decode the
//!     embedded `ValidWalletUpdateStatement` and pre-compute
//!     `old_pk_root_eth_addr` so downstream phases (resolve-addresses,
//!     reconstruct-balances) need zero RPC and zero crypto work.
//!
//! Resumability: a `CHECKPOINT.events` file records the last
//! fully-completed event-enumeration block, so a crashed run can resume
//! exactly where it left off. The tx-fetch step deduplicates against the
//! tx file's existing tx_hashes — re-running is always safe.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use alloy::consensus::Transaction as _;
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy_sol_types::SolCall;
use clap::Parser;
use darkpool_client::arbitrum::abi::{Darkpool::updateWalletCall, UPDATE_WALLET_SELECTOR};
use darkpool_client::arbitrum::contract_types::types::{
    PublicSigningKey, ValidWalletUpdateStatement as ContractStmt,
};
use darkpool_client::arbitrum::helpers::deserialize_calldata;
use eyre::{Result, WrapErr, eyre};
use futures::stream::{FuturesUnordered, StreamExt};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

const PROXY_ADDR_STR: &str = "0x30bD8eAb29181F790D7e495786d4B96d7AfDC518";
/// V1 deploy block (2024-09-03T21:48:00Z).
const DEPLOY_BLOCK: u64 = 249_786_497;
/// Block of the attack tx (2026-05-10T08:27:23Z). Inclusive — the attack
/// tx itself is part of the on-chain truth for reconciliation.
const ATTACK_BLOCK: u64 = 461_301_926;

#[derive(Parser, Debug)]
struct Cli {
    /// Arbitrum One RPC URL. Reads $RPC_URL if unset.
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,
    /// Output directory. Created if missing.
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long, default_value_t = DEPLOY_BLOCK)]
    from_block: u64,
    #[arg(long, default_value_t = ATTACK_BLOCK)]
    to_block: u64,
    /// Block range per eth_getLogs call.
    #[arg(long, default_value_t = 2_000_000)]
    chunk_size: u64,
    /// Concurrent eth_getTransactionByHash calls.
    #[arg(long, default_value_t = 16)]
    tx_concurrency: usize,
    /// If set, ignore the checkpoint and re-enumerate from --from-block.
    /// The output JSONL files are NOT truncated — the caller is responsible
    /// for deleting them first if they want a clean slate.
    #[arg(long, default_value_t = false)]
    rebuild_events: bool,
    /// If set, skip event enumeration entirely and only run the tx-fetch
    /// pass against the existing event files. Useful when the event ingest
    /// already finished and you just need to backfill the tx cache.
    #[arg(long, default_value_t = false)]
    txs_only: bool,
}

// === Output schemas === //

#[derive(Serialize, Deserialize)]
struct ExternalTransferRow {
    block: u64,
    tx_hash: String,
    log_index: u64,
    account: String,
    mint: String,
    is_withdrawal: bool,
    amount: String, // decimal U256
}

#[derive(Serialize, Deserialize)]
struct WalletUpdatedRow {
    block: u64,
    tx_hash: String,
    log_index: u64,
    /// 32-byte hex (no 0x prefix). The wallet's `public_blinder_share` at
    /// the time this updateWallet was applied.
    wallet_blinder_share: String,
}

#[derive(Serialize, Deserialize)]
struct UpdateWalletTxRow {
    tx_hash: String,
    block: u64,
    from: String,
    /// "0x" + 4 hex bytes.
    selector: String,
    /// True iff the top-level selector is `updateWallet`. False for
    /// wrappers (gas-sponsor, ERC-4337, CoW, etc.) — those still emit
    /// `ExternalTransfer` events but their top-level calldata can't be
    /// decoded as `updateWalletCall`. Phase 3 may need to fall back to
    /// `debug_traceTransaction` for those; phase 4 ignores them.
    is_update_wallet: bool,
    /// Pre-computed `keccak256(secp256k1_pubkey_xy)[12..]` derived from
    /// `statement.old_pk_root`. Only set when `is_update_wallet=true`.
    old_pk_root_eth_addr: Option<String>,
    /// Raw `valid_wallet_update_statement_bytes` (postcard-encoded) as
    /// hex. Kept so reconstruct-balances can walk the blinder stream
    /// without re-fetching the tx. Only set when `is_update_wallet=true`.
    valid_wallet_update_statement_bytes_hex: Option<String>,
}

// === Crypto helpers === //

fn external_transfer_topic0() -> B256 {
    keccak256(b"ExternalTransfer(address,address,bool,uint256)")
}

fn wallet_updated_topic0() -> B256 {
    keccak256(b"WalletUpdated(uint256)")
}

fn pk_root_to_eth_addr(pk: &PublicSigningKey) -> Result<Address> {
    use circuit_types::keychain::{NonNativeScalar, PublicSigningKey as CircuitPk};
    use constants::Scalar;
    let circuit_pk = CircuitPk {
        x: NonNativeScalar {
            scalar_words: [Scalar::new(pk.x[0]), Scalar::new(pk.x[1])],
        },
        y: NonNativeScalar {
            scalar_words: [Scalar::new(pk.y[0]), Scalar::new(pk.y[1])],
        },
    };
    let vk: VerifyingKey = (&circuit_pk).into();
    let enc = vk.to_encoded_point(false /* compressed */);
    let bytes = enc.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(eyre!("bad SEC1 encoding: {} bytes", bytes.len()));
    }
    let hash = keccak256(&bytes[1..65]);
    Ok(Address::from_slice(&hash.0[12..32]))
}

// === Event enumeration === //

/// Fetch logs for [from, to]. If the RPC returns "Log response size
/// exceeded" (Alchemy's 10k-log cap), halve the range and recurse.
fn fetch_logs<'a, P: Provider + Sync>(
    provider: &'a P,
    proxy: Address,
    topic0: B256,
    from: u64,
    to: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<alloy::rpc::types::Log>>> + Send + 'a>>
{
    Box::pin(async move {
        let filter = Filter::new()
            .address(proxy)
            .event_signature(topic0)
            .from_block(from)
            .to_block(to);
        match provider.get_logs(&filter).await {
            Ok(logs) => Ok(logs),
            Err(e) => {
                let err_str = format!("{e}");
                if err_str.contains("Log response size exceeded") && to > from {
                    let mid = from + (to - from) / 2;
                    tracing::info!(
                        "    log cap hit on [{from}, {to}], halving → [{from}, {mid}] + [{}, {to}]",
                        mid + 1
                    );
                    let mut a = fetch_logs(provider, proxy, topic0, from, mid).await?;
                    let mut b = fetch_logs(provider, proxy, topic0, mid + 1, to).await?;
                    a.append(&mut b);
                    Ok(a)
                } else {
                    Err(eyre!("eth_getLogs [{from}, {to}]: {e}"))
                }
            }
        }
    })
}

fn write_xfer_row(w: &mut impl Write, log: &alloy::rpc::types::Log) -> Result<bool> {
    let topics = log.topics();
    if topics.len() < 4 {
        return Ok(false);
    }
    let account = Address::from_slice(&topics[1].0[12..32]);
    let mint = Address::from_slice(&topics[2].0[12..32]);
    let is_withdrawal = topics[3].0[31] != 0;
    let data = log.data().data.as_ref();
    if data.len() < 32 {
        return Ok(false);
    }
    let amount = U256::from_be_slice(&data[..32]);
    let row = ExternalTransferRow {
        block: log.block_number.unwrap_or(0),
        tx_hash: format!("0x{}", hex::encode(log.transaction_hash.unwrap_or(B256::ZERO))),
        log_index: log.log_index.unwrap_or(0),
        account: format!("0x{:x}", account),
        mint: format!("0x{:x}", mint),
        is_withdrawal,
        amount: amount.to_string(),
    };
    serde_json::to_writer(&mut *w, &row)?;
    writeln!(w)?;
    Ok(true)
}

fn write_wu_row(w: &mut impl Write, log: &alloy::rpc::types::Log) -> Result<bool> {
    let topics = log.topics();
    if topics.len() < 2 {
        return Ok(false);
    }
    let row = WalletUpdatedRow {
        block: log.block_number.unwrap_or(0),
        tx_hash: format!("0x{}", hex::encode(log.transaction_hash.unwrap_or(B256::ZERO))),
        log_index: log.log_index.unwrap_or(0),
        wallet_blinder_share: hex::encode(topics[1].0),
    };
    serde_json::to_writer(&mut *w, &row)?;
    writeln!(w)?;
    Ok(true)
}

async fn enumerate_events(
    provider: &impl Provider,
    proxy: Address,
    xfer_path: &PathBuf,
    wu_path: &PathBuf,
    checkpoint_path: &PathBuf,
    from_block: u64,
    to_block: u64,
    chunk_size: u64,
) -> Result<()> {
    let xfer_topic = external_transfer_topic0();
    let wu_topic = wallet_updated_topic0();

    let xfer_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(xfer_path)?;
    let mut xfer_w = BufWriter::new(xfer_file);
    let wu_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(wu_path)?;
    let mut wu_w = BufWriter::new(wu_file);

    let mut cursor = from_block;
    let mut total_xfers = 0usize;
    let mut total_wus = 0usize;
    while cursor <= to_block {
        let chunk_hi = (cursor + chunk_size - 1).min(to_block);
        // Two log queries per chunk — fire concurrently.
        let (xfers, wus) = tokio::try_join!(
            fetch_logs(provider, proxy, xfer_topic, cursor, chunk_hi),
            fetch_logs(provider, proxy, wu_topic, cursor, chunk_hi),
        )?;
        for log in xfers.iter() {
            write_xfer_row(&mut xfer_w, log)?;
        }
        for log in wus.iter() {
            write_wu_row(&mut wu_w, log)?;
        }
        // Flush BOTH writers AND THEN checkpoint atomically. Order matters:
        // if we checkpointed first and then crashed mid-write, resume would
        // skip un-flushed events.
        xfer_w.flush()?;
        wu_w.flush()?;
        std::fs::write(checkpoint_path, format!("{chunk_hi}\n"))?;
        total_xfers += xfers.len();
        total_wus += wus.len();
        tracing::info!(
            "  [{}, {}]: xfers={} wus={} (cumulative xfers={}, wus={})",
            cursor,
            chunk_hi,
            xfers.len(),
            wus.len(),
            total_xfers,
            total_wus,
        );
        cursor = chunk_hi + 1;
    }
    tracing::info!("event enum done: {} xfers, {} wus", total_xfers, total_wus);
    Ok(())
}

// === Tx fetch === //

async fn fetch_tx_row(provider: &impl Provider, tx_hash: B256) -> Result<UpdateWalletTxRow> {
    let tx = provider
        .get_transaction_by_hash(tx_hash)
        .await
        .wrap_err("eth_getTransactionByHash")?
        .ok_or_else(|| eyre!("tx {} not found", tx_hash))?;
    let calldata: &[u8] = tx.input();
    let from_addr = format!("0x{:x}", tx.inner.signer());
    let block = tx.block_number.unwrap_or(0);
    let tx_hash_str = format!("0x{}", hex::encode(tx_hash));

    let (selector_str, is_update_wallet, old_pk_addr, stmt_hex) = if calldata.len() >= 4 {
        let selector: [u8; 4] = calldata[..4].try_into().unwrap();
        let sel_str = format!("0x{}", hex::encode(selector));
        if selector == UPDATE_WALLET_SELECTOR {
            // Try to decode. Failure is logged but not fatal — we still
            // record the row so the next run doesn't re-fetch this tx.
            let mut old_addr: Option<String> = None;
            let mut bytes_hex: Option<String> = None;
            match updateWalletCall::abi_decode(calldata) {
                Ok(call) => {
                    let bytes = call.valid_wallet_update_statement_bytes.as_ref();
                    bytes_hex = Some(format!("0x{}", hex::encode(bytes)));
                    match deserialize_calldata::<ContractStmt>(bytes) {
                        Ok(stmt) => match pk_root_to_eth_addr(&stmt.old_pk_root) {
                            Ok(a) => old_addr = Some(format!("0x{:x}", a)),
                            Err(e) => tracing::warn!(
                                "{}: pk_root_to_eth_addr failed: {e:#}",
                                tx_hash_str
                            ),
                        },
                        Err(e) => tracing::warn!(
                            "{}: deserialize statement failed: {e:?}",
                            tx_hash_str
                        ),
                    }
                }
                Err(e) => tracing::warn!("{}: abi_decode updateWallet failed: {e}", tx_hash_str),
            }
            (sel_str, true, old_addr, bytes_hex)
        } else {
            (sel_str, false, None, None)
        }
    } else {
        ("0x".to_string(), false, None, None)
    };

    Ok(UpdateWalletTxRow {
        tx_hash: tx_hash_str,
        block,
        from: from_addr,
        selector: selector_str,
        is_update_wallet,
        old_pk_root_eth_addr: old_pk_addr,
        valid_wallet_update_statement_bytes_hex: stmt_hex,
    })
}

fn collect_tx_hashes(path: &PathBuf, field: &str) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    if !path.exists() {
        return Ok(out);
    }
    let f = std::fs::File::open(path)?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let v: serde_json::Value = serde_json::from_str(&line)?;
        if let Some(h) = v.get(field).and_then(|x| x.as_str()) {
            out.insert(h.to_lowercase());
        }
    }
    Ok(out)
}

async fn fetch_missing_txs(
    provider: Arc<impl Provider + 'static>,
    xfer_path: &PathBuf,
    wu_path: &PathBuf,
    tx_path: &PathBuf,
    concurrency: usize,
) -> Result<()> {
    let xfer_txs = collect_tx_hashes(xfer_path, "tx_hash")?;
    let wu_txs = collect_tx_hashes(wu_path, "tx_hash")?;
    let cached = collect_tx_hashes(tx_path, "tx_hash")?;
    let mut all: HashSet<String> = xfer_txs;
    all.extend(wu_txs);
    let to_fetch: Vec<String> = all.difference(&cached).cloned().collect();
    tracing::info!(
        "tx cache: {} total referenced, {} cached, {} to fetch",
        all.len(),
        cached.len(),
        to_fetch.len()
    );
    if to_fetch.is_empty() {
        return Ok(());
    }

    let tx_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(tx_path)?;
    let writer = Arc::new(Mutex::new(BufWriter::new(tx_file)));
    let sem = Arc::new(Semaphore::new(concurrency));
    let total = to_fetch.len();
    let report_every = (total / 100).max(50);

    let mut futs = FuturesUnordered::new();
    for tx_hex in to_fetch.into_iter() {
        let h: B256 = tx_hex.parse()?;
        let sem = sem.clone();
        let prov = provider.clone();
        let w = writer.clone();
        futs.push(tokio::spawn(async move {
            let _p = sem.acquire().await.unwrap();
            match fetch_tx_row(prov.as_ref(), h).await {
                Ok(row) => {
                    let line = serde_json::to_string(&row).unwrap();
                    let mut g = w.lock().unwrap();
                    writeln!(*g, "{line}").unwrap();
                    Ok::<(), ()>(())
                }
                Err(e) => {
                    tracing::warn!("fetch tx 0x{} failed: {e:#}", hex::encode(h));
                    Err(())
                }
            }
        }));
    }
    let mut done = 0usize;
    let mut errors = 0usize;
    while let Some(j) = futs.next().await {
        match j {
            Ok(Ok(())) => {}
            Ok(Err(())) => errors += 1,
            Err(e) => {
                tracing::warn!("task join error: {e}");
                errors += 1;
            }
        }
        done += 1;
        if done % report_every == 0 {
            tracing::info!("tx fetch progress: {}/{} ({} errors)", done, total, errors);
        }
    }
    writer.lock().unwrap().flush()?;
    tracing::info!("tx fetch done: {} fetched, {} errors", done - errors, errors);
    Ok(())
}

// === main === //

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ingest=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.out_dir)?;
    let xfer_path = cli.out_dir.join("external-transfers.jsonl");
    let wu_path = cli.out_dir.join("wallet-updated.jsonl");
    let tx_path = cli.out_dir.join("update-wallet-txs.jsonl");
    let checkpoint_path = cli.out_dir.join("CHECKPOINT.events");

    let proxy: Address = PROXY_ADDR_STR.parse()?;
    let provider = ProviderBuilder::new().connect_http(cli.rpc_url.parse()?);

    if !cli.txs_only {
        // Determine resume point.
        let resume_from = if cli.rebuild_events {
            cli.from_block
        } else if let Ok(s) = std::fs::read_to_string(&checkpoint_path) {
            let last: u64 = s.trim().parse().unwrap_or(0);
            if last >= cli.to_block {
                tracing::info!("checkpoint already at to_block; skipping event enum");
                cli.to_block + 1
            } else {
                let next = (last + 1).max(cli.from_block);
                tracing::info!("resuming events from block {} (checkpoint={last})", next);
                next
            }
        } else {
            cli.from_block
        };
        if resume_from <= cli.to_block {
            tracing::info!(
                "enumerating events [{resume_from}, {}] in chunks of {}",
                cli.to_block,
                cli.chunk_size
            );
            enumerate_events(
                &provider,
                proxy,
                &xfer_path,
                &wu_path,
                &checkpoint_path,
                resume_from,
                cli.to_block,
                cli.chunk_size,
            )
            .await?;
        }
    }

    // Tx fetch always runs (idempotent).
    let provider = Arc::new(provider);
    fetch_missing_txs(provider, &xfer_path, &wu_path, &tx_path, cli.tx_concurrency).await?;

    Ok(())
}
