//! redeem-v1-fees-onchain
//!
//! Headless redemption of v1 darkpool fees, intended for chains whose live
//! v1 relayer has been wound down (e.g. arbitrum-one).
//!
//! ## Phases
//!
//! 0. `inspect`  — DB-only: list unredeemed fees + fee-redemption wallets.
//!                 No on-chain reads, no writes. (THIS PHASE)
//! 1. `reconstruct-wallet` — walk a fee wallet's blinder stream on-chain to
//!                            recover its current state.
//! 2. `decrypt-note` — fetch + decrypt a single fee note from its tx.
//! 3. `prove-redeem` — generate a ValidFeeRedemption proof for one note
//!                      (no submission).
//! 4. `submit-redeem` — submit one note redemption on-chain.
//! 5. `submit-withdraw` — withdraw fee-wallet balances to the FeeRedemption EOA.
//!
//! Phase 0 only reads. Every later phase will be gated behind `--execute`
//! to prevent accidental writes.

use std::{collections::HashMap, str::FromStr};

use clap::{Parser, Subcommand, ValueEnum};
use eyre::{Result, WrapErr, eyre};
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use serde::Deserialize;
use tokio_postgres::Config as PgConfig;
use uuid::Uuid;

/// Tickers pinned at $1.00 (mirrors price-reporter-client::UNIT_PRICE_TICKERS).
const STABLE_TICKERS: &[&str] = &["USDC", "USDT", "USD"];

// --- CLI -------------------------------------------------------------------

#[derive(Parser, Debug)]
#[clap(about = "Headless redemption of v1 darkpool fees")]
struct Cli {
    /// Postgres URL for the funds-manager DB. If not provided, the tool
    /// reads the AWS Secrets Manager secret named by --db-secret-name.
    #[clap(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    /// AWS Secrets Manager secret holding the funds-manager DB URL.
    #[clap(long, env = "DB_SECRET_NAME", default_value = "/mainnet/funds-manager-db-url")]
    db_secret_name: String,

    /// AWS region for Secrets Manager.
    #[clap(long, env = "AWS_REGION", default_value = "us-east-2")]
    aws_region: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// DB-only inventory of unredeemed fees and fee-redemption wallets.
    Inspect(InspectArgs),

    /// Reconstruct a fee-redemption wallet's current state from on-chain
    /// calldata + its AWS-stored root key. Read-only. (Phase 1)
    ReconstructWallet(ReconstructWalletArgs),

    /// Estimate the gas cost (in USD) of redeeming N notes on arb1. Pulls
    /// current arb1 L2 gas price via eth_gasPrice and current ETH price from
    /// the Renegade price reporter (via the WETH mint).
    EstimateGas(EstimateGasArgs),

    /// Sort unredeemed notes by USD value desc, intersect with live per-tx
    /// gas cost, print cumulative-value-vs-rank + breakeven. Drives the
    /// scope decision for redemption: how many notes are individually
    /// profitable to redeem? (Phase 1.5)
    ValueCurve(ValueCurveArgs),
}

#[derive(Parser, Debug)]
struct InspectArgs {
    /// Which chain to inspect. The funds-manager DB stores
    /// `chain = 'arbitrum'` for both arbitrum-one and arbitrum-sepolia;
    /// pick the right DB to scope to mainnet vs testnet.
    #[clap(long, value_enum)]
    chain: ChainArg,

    /// Renegade price reporter base URL.
    #[clap(
        long,
        env = "PRICE_REPORTER_URL",
        default_value = "https://mainnet.price-reporter.renegade.fi:3000"
    )]
    price_reporter_url: String,

    /// Base URL where per-chain token-mapping JSON files live. The tool fetches
    /// `<base>/arbitrum-one.json` and `<base>/base-mainnet.json` for decimals
    /// and tickers.
    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main"
    )]
    token_mappings_base_url: String,

    /// Maximum number of per-note rows to print before truncating. Per-mint
    /// totals are always shown. Pass `--all` to dump everything.
    #[clap(long, default_value_t = 20)]
    max_note_rows: usize,

    /// Print every unredeemed fee row (overrides --max-note-rows).
    #[clap(long)]
    all: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ChainArg {
    /// arbitrum-one (DB chain column = "arbitrum")
    ArbitrumOne,
    /// base-mainnet (DB chain column = "base")
    BaseMainnet,
}

impl ChainArg {
    fn db_value(self) -> &'static str {
        match self {
            ChainArg::ArbitrumOne => "arbitrum",
            ChainArg::BaseMainnet => "base",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            ChainArg::ArbitrumOne => "arbitrum-one",
            ChainArg::BaseMainnet => "base-mainnet",
        }
    }

    /// AWS Secrets Manager prefix for chain-specific secrets. Mirrors
    /// `funds-manager-server/src/helpers.rs:get_secret_prefix`.
    fn secret_prefix(self) -> &'static str {
        match self {
            ChainArg::ArbitrumOne => "/arbitrum/one",
            ChainArg::BaseMainnet => "/base/mainnet",
        }
    }

    /// EIP-155 chain ID. Needed for `derive_wallet_keychain` since the v1
    /// derivation message includes the chain id.
    fn chain_id(self) -> u64 {
        match self {
            ChainArg::ArbitrumOne => 42_161,
            ChainArg::BaseMainnet => 8_453,
        }
    }
}

#[derive(Parser, Debug)]
struct ValueCurveArgs {
    /// Which chain's unredeemed fees to analyze.
    #[clap(long, value_enum)]
    chain: ChainArg,

    /// RPC URL (used for eth_gasPrice). If empty, resolved from AWS Secrets
    /// Manager at `<chain-prefix>/rpc-url`.
    #[clap(long, default_value = "")]
    rpc_url: String,

    /// Renegade price reporter base URL.
    #[clap(
        long,
        env = "PRICE_REPORTER_URL",
        default_value = "https://mainnet.price-reporter.renegade.fi:3000"
    )]
    price_reporter_url: String,

    /// Token mappings base URL.
    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main"
    )]
    token_mappings_base_url: String,

    /// L2 gas budget per `redeem_fee` tx. Same default as `estimate-gas`.
    #[clap(long, default_value_t = 800_000u64)]
    gas_per_tx: u64,

    /// Cumulative-rank milestones to show in the curve table. The total
    /// count of priceable notes is always appended.
    #[clap(long, value_delimiter = ',', default_values_t = vec![10u64, 100, 1_000, 10_000])]
    milestones: Vec<u64>,
}

#[derive(Parser, Debug)]
struct EstimateGasArgs {
    /// Which chain to estimate against. Only arbitrum-one is currently
    /// supported (base v1 redemption goes through its live relayer).
    #[clap(long, value_enum, default_value = "arbitrum-one")]
    chain: ChainArg,

    /// RPC URL for the chain. If empty (the default), resolved from AWS
    /// Secrets Manager at `<chain-prefix>/rpc-url` — same secret the
    /// gardener reads.
    #[clap(long, default_value = "")]
    rpc_url: String,

    /// Renegade price reporter base URL for the ETH USD price.
    #[clap(
        long,
        env = "PRICE_REPORTER_URL",
        default_value = "https://mainnet.price-reporter.renegade.fi:3000"
    )]
    price_reporter_url: String,

    /// Token mappings base URL (to look up the chain's WETH mint).
    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main"
    )]
    token_mappings_base_url: String,

    /// L2 gas budget per `redeem_fee` tx. Empirical sanity-check pending;
    /// 800k is a conservative midpoint for a single Plonk verifier + a
    /// state update. Override after we measure real txs.
    #[clap(long, default_value_t = 800_000u64)]
    gas_per_tx: u64,

    /// Sizes to project at (in addition to the actual unredeemed-note count
    /// pulled from the DB).
    #[clap(long, value_delimiter = ',', default_values_t = vec![100u64, 1_000, 10_000])]
    sizes: Vec<u64>,

    /// Total USD value of unredeemed notes on this chain — used to show the
    /// net (value − gas). Optional. If omitted, only the gross cost is
    /// shown.
    #[clap(long)]
    total_value_usd: Option<f64>,
}

#[derive(Parser, Debug)]
struct ReconstructWalletArgs {
    /// Which chain the fee wallet lives on.
    #[clap(long, value_enum)]
    chain: ChainArg,

    /// Fee wallet UUID. If omitted, the tool pulls all fee wallets for
    /// the selected chain from the funds-manager DB and reconstructs each
    /// in sequence.
    #[clap(long)]
    wallet_id: Option<Uuid>,

    /// RPC URL for the chain. If empty (the default), resolved from AWS
    /// Secrets Manager at `<chain-prefix>/rpc-url` — e.g.
    /// `/arbitrum/one/rpc-url` for arbitrum-one. Same secret the gardener
    /// reads.
    #[clap(long, default_value = "")]
    rpc_url: String,

    /// Skip the on-chain walk; just verify derived seeds match the
    /// supplied wallet_id.
    #[clap(long)]
    no_walk: bool,

    /// Renegade price reporter base URL (used for USD valuation of
    /// reconstructed balances).
    #[clap(
        long,
        env = "PRICE_REPORTER_URL",
        default_value = "https://mainnet.price-reporter.renegade.fi:3000"
    )]
    price_reporter_url: String,

    /// Base URL for per-chain token-mappings JSON (for decimals + tickers).
    #[clap(
        long,
        default_value = "https://raw.githubusercontent.com/renegade-fi/token-mappings/main"
    )]
    token_mappings_base_url: String,

    /// Directory for resumable walk checkpoints. Defaults to
    /// `$HOME/.cache/redeem-v1-fees-onchain`. One JSON file per
    /// (chain, wallet_id).
    #[clap(long)]
    checkpoint_dir: Option<String>,

    /// Discard any existing checkpoint and walk from genesis.
    #[clap(long)]
    from_scratch: bool,

    /// Write a checkpoint every N applied updates.
    #[clap(long, default_value_t = 500)]
    checkpoint_every: usize,
}

// --- Main ------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let Cli { database_url, db_secret_name, aws_region, command } = cli;
    match command {
        Command::Inspect(args) => {
            let db_url =
                resolve_database_url(database_url.as_deref(), &db_secret_name, &aws_region).await?;
            run_inspect(args, &db_url).await
        }
        Command::ReconstructWallet(args) => {
            let db_url =
                resolve_database_url(database_url.as_deref(), &db_secret_name, &aws_region).await?;
            run_reconstruct_wallet(args, &aws_region, &db_url).await
        }
        Command::EstimateGas(args) => {
            let db_url =
                resolve_database_url(database_url.as_deref(), &db_secret_name, &aws_region).await?;
            run_estimate_gas(args, &db_url, &aws_region).await
        }
        Command::ValueCurve(args) => {
            let db_url =
                resolve_database_url(database_url.as_deref(), &db_secret_name, &aws_region).await?;
            run_value_curve(args, &db_url, &aws_region).await
        }
    }
}

async fn resolve_database_url(
    database_url: Option<&str>,
    db_secret_name: &str,
    aws_region: &str,
) -> Result<String> {
    if let Some(url) = database_url {
        return Ok(url.to_string());
    }
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(aws_region.to_string()))
        .load()
        .await;
    let client = aws_sdk_secretsmanager::Client::new(&cfg);
    let resp = client
        .get_secret_value()
        .secret_id(db_secret_name)
        .send()
        .await
        .with_context(|| format!("get_secret_value({db_secret_name})"))?;
    let secret = resp
        .secret_string()
        .ok_or_else(|| eyre!("secret {db_secret_name} has no SecretString"))?;
    Ok(secret.trim().to_string())
}

// --- Inspect ---------------------------------------------------------------

async fn run_inspect(args: InspectArgs, db_url: &str) -> Result<()> {
    let chain_db = args.chain.db_value();
    let chain_disp = args.chain.display_name();
    println!("================================================================");
    println!("redeem-v1-fees-onchain inspect");
    println!("  chain (DB):      {chain_db}");
    println!("  chain (display): {chain_disp}");
    println!("  price-reporter:  {}", args.price_reporter_url);
    println!("================================================================");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .wrap_err("building reqwest client")?;

    // Token index for this chain — lowercase mint -> (ticker, decimals)
    let token_index = fetch_token_index(&http, &args.token_mappings_base_url, args.chain)
        .await
        .wrap_err_with(|| format!("loading token mappings for {chain_disp}"))?;

    let client = connect_pg(db_url).await?;

    // --- Unredeemed fees --- //
    let fees = load_unredeemed_fees(&client, chain_db).await?;
    let totals = aggregate_by_mint(&fees);

    // Fetch prices for distinct mints. USDC/USDT/USD short-circuit at $1.
    let prices = fetch_prices(
        &http,
        &args.price_reporter_url,
        &token_index,
        totals.iter().map(|(m, _, _)| m.clone()).collect::<Vec<_>>(),
    )
    .await;

    println!("\nunredeemed fee totals by mint:");
    let priced_totals = build_priced_totals(&totals, &token_index, &prices);
    print_priced_totals(&priced_totals);

    // Per-note table (truncated by default — there can be hundreds of thousands)
    println!("\nunredeemed fee rows ({} total):", fees.len());
    if fees.is_empty() {
        println!("  (none)");
    } else if args.all {
        print_fees(&fees, &token_index, fees.len());
    } else {
        print_fees(&fees, &token_index, args.max_note_rows);
    }

    // --- Fee redemption wallets --- //
    let wallets = load_fee_wallets(&client, chain_db).await?;
    println!("\nfee-redemption wallets ({} rows):", wallets.len());
    if wallets.is_empty() {
        println!("  (none — `redeem_fees` has never created a fee wallet on this chain)");
    } else {
        print_wallets(&wallets);
    }

    // --- Grand total --- //
    let known_usd: f64 = priced_totals.iter().filter_map(|t| t.usd_value).sum();
    let unknown_rows: usize = priced_totals.iter().filter(|t| t.usd_value.is_none()).count();
    let total_notes: usize = totals.iter().map(|(_, _, n)| *n).sum();
    let distinct_mints = totals.len();

    println!("\n================================================================");
    println!("SUMMARY ({chain_disp})");
    println!("  notes:           {total_notes}");
    println!("  distinct mints:  {distinct_mints}");
    println!("  fee wallets:     {}", wallets.len());
    if unknown_rows == 0 {
        println!("  total redeemable: ${known_usd:.2}");
    } else {
        println!("  total redeemable: ${known_usd:.2} ({unknown_rows} mint(s) excluded — missing ticker, decimals, or price)");
    }
    println!("================================================================");

    println!("\nNotes:");
    println!("  * Amounts shown raw (token base units) and decimal-adjusted via token-mappings.");
    println!("  * USDC/USDT/USD pinned at $1.00; all other prices via the Renegade price reporter.");
    println!("  * `receiver` is the encryption-pubkey hex; the funds-manager picks the");
    println!("    matching decryption key (relayer_decryption_key or protocol_decryption_key)");
    println!("    from chain_configs.json at redemption time.");
    println!("  * Each fee wallet's eth root key lives in AWS Secrets Manager under");
    println!("    `<env>/redemption-wallet-<wallet-id>`. Phase 1 will derive seeds + keychain");
    println!("    from those keys and walk each wallet's on-chain commitment stream.");
    Ok(())
}

// --- DB plumbing -----------------------------------------------------------

async fn connect_pg(db_url: &str) -> Result<tokio_postgres::Client> {
    // Always use TLS — prod RDS rejects plaintext.
    let tls = TlsConnector::builder()
        .danger_accept_invalid_certs(true) // RDS cert chain is valid; toggle if you prefer strict
        .build()
        .wrap_err("building TLS connector")?;
    let connector = MakeTlsConnector::new(tls);

    let cfg = PgConfig::from_str(db_url).wrap_err("parsing DATABASE_URL")?;
    let (client, conn) = cfg.connect(connector).await.wrap_err("connecting to Postgres")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!("postgres connection error: {e}");
        }
    });
    Ok(client)
}

#[derive(Debug, Clone)]
struct Fee {
    id: i32,
    tx_hash: String,
    mint: String,
    amount_raw: u128,
    /// Blinder kept as text — large Numeric value, we never math on it here.
    /// Phase 2 (note decryption) will need it to confirm note commitments.
    #[allow(dead_code)]
    blinder: String,
    receiver: String,
}

async fn load_unredeemed_fees(client: &tokio_postgres::Client, chain: &str) -> Result<Vec<Fee>> {
    // tokio-postgres has no native Numeric -> integer codec, so cast to text
    // in SQL and parse on the Rust side. Fee amounts are token base units and
    // fit comfortably in u128.
    let rows = client
        .query(
            "SELECT id, tx_hash, mint, amount::text, blinder::text, receiver \
             FROM fees \
             WHERE chain = $1 AND redeemed = false \
             ORDER BY mint, id",
            &[&chain],
        )
        .await
        .wrap_err("query fees")?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: i32 = r.get(0);
        let amount_str: String = r.get(3);
        let amount_raw: u128 = amount_str
            .parse()
            .wrap_err_with(|| format!("parsing fee.amount '{amount_str}' as u128 (id={id})"))?;
        out.push(Fee {
            id,
            tx_hash: r.get(1),
            mint: r.get(2),
            amount_raw,
            blinder: r.get(4),
            receiver: r.get(5),
        });
    }
    Ok(out)
}

fn aggregate_by_mint(fees: &[Fee]) -> Vec<(String, u128, usize)> {
    let mut acc: std::collections::BTreeMap<String, (u128, usize)> =
        std::collections::BTreeMap::new();
    for f in fees {
        let entry = acc.entry(f.mint.clone()).or_insert((0u128, 0));
        entry.0 = entry.0.saturating_add(f.amount_raw);
        entry.1 += 1;
    }
    acc.into_iter().map(|(mint, (sum, n))| (mint, sum, n)).collect()
}

#[derive(Debug, Clone)]
struct FeeWallet {
    id: Uuid,
    mints: Vec<Option<String>>,
    secret_id: String,
}

async fn load_fee_wallets(client: &tokio_postgres::Client, chain: &str) -> Result<Vec<FeeWallet>> {
    let rows = client
        .query(
            "SELECT id, mints, secret_id \
             FROM renegade_wallets \
             WHERE chain = $1 \
             ORDER BY id",
            &[&chain],
        )
        .await
        .wrap_err("query renegade_wallets")?;
    Ok(rows
        .into_iter()
        .map(|r| FeeWallet { id: r.get(0), mints: r.get(1), secret_id: r.get(2) })
        .collect())
}

// --- Token mappings + price reporter ---------------------------------------

#[derive(Deserialize, Debug, Clone)]
struct TokenMappingFile {
    tokens: Vec<TokenInfo>,
}

#[derive(Deserialize, Debug, Clone)]
struct TokenInfo {
    ticker: String,
    address: String,
    decimals: u32,
}

type TokenIndex = HashMap<String, TokenInfo>;

async fn fetch_token_index(
    http: &reqwest::Client,
    base_url: &str,
    chain: ChainArg,
) -> Result<TokenIndex> {
    let url = format!("{}/{}.json", base_url.trim_end_matches('/'), chain.display_name());
    let body = http
        .get(&url)
        .send()
        .await
        .wrap_err_with(|| format!("GET {url}"))?
        .error_for_status()
        .wrap_err_with(|| format!("token-mappings status check for {url}"))?
        .text()
        .await
        .wrap_err_with(|| format!("reading body for {url}"))?;
    let parsed: TokenMappingFile =
        serde_json::from_str(&body).wrap_err_with(|| format!("parsing JSON from {url}"))?;
    let mut map = HashMap::new();
    for t in parsed.tokens {
        map.insert(t.address.to_lowercase(), t);
    }
    Ok(map)
}

type PriceMap = HashMap<String, f64>;

async fn fetch_prices(
    http: &reqwest::Client,
    base_url: &str,
    token_index: &TokenIndex,
    mints: Vec<String>,
) -> PriceMap {
    let mut out: PriceMap = HashMap::new();
    for mint in mints {
        let mint_lc = mint.to_lowercase();
        if out.contains_key(&mint_lc) {
            continue;
        }
        let ticker_upper = token_index
            .get(&mint_lc)
            .map(|t| t.ticker.to_uppercase())
            .unwrap_or_default();
        if STABLE_TICKERS.iter().any(|t| *t == ticker_upper) {
            out.insert(mint_lc, 1.0);
            continue;
        }
        match fetch_price_http(http, base_url, &mint_lc).await {
            Ok(p) => {
                out.insert(mint_lc, p);
            }
            Err(e) => {
                eprintln!(
                    "  [warn] price lookup failed for mint={mint_lc} ticker={ticker_upper}: {e}"
                );
            }
        }
    }
    out
}

async fn fetch_price_http(http: &reqwest::Client, base_url: &str, mint_lc: &str) -> Result<f64> {
    let url = format!("{}/price/renegade-{mint_lc}", base_url.trim_end_matches('/'));
    let resp = http.get(&url).send().await.wrap_err_with(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eyre::bail!("GET {url} -> {s}: {body}");
    }
    let text = resp.text().await.wrap_err("reading price body")?;
    let p: f64 = text
        .trim()
        .parse()
        .wrap_err_with(|| format!("parsing price '{text}' as f64 for {mint_lc}"))?;
    Ok(p)
}

// --- Priced totals ---------------------------------------------------------

#[derive(Debug, Clone)]
struct PricedTotal {
    mint: String,
    ticker: Option<String>,
    decimals: Option<u32>,
    raw: u128,
    n_notes: usize,
    price_usd: Option<f64>,
    decimal_amount: Option<f64>,
    usd_value: Option<f64>,
}

fn build_priced_totals(
    totals: &[(String, u128, usize)],
    token_index: &TokenIndex,
    prices: &PriceMap,
) -> Vec<PricedTotal> {
    let mut out: Vec<PricedTotal> = totals
        .iter()
        .map(|(mint, raw, n)| {
            let mint_lc = mint.to_lowercase();
            let info = token_index.get(&mint_lc);
            let ticker = info.map(|t| t.ticker.clone());
            let decimals = info.map(|t| t.decimals);
            let price_usd = prices.get(&mint_lc).copied();
            let decimal_amount = decimals.map(|d| (*raw as f64) / 10f64.powi(d as i32));
            let usd_value = match (decimal_amount, price_usd) {
                (Some(a), Some(p)) => Some(a * p),
                _ => None,
            };
            PricedTotal {
                mint: mint.clone(),
                ticker,
                decimals,
                raw: *raw,
                n_notes: *n,
                price_usd,
                decimal_amount,
                usd_value,
            }
        })
        .collect();
    // Sort: highest USD value first, unknowns last.
    out.sort_by(|a, b| match (b.usd_value, a.usd_value) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.mint.cmp(&b.mint),
    });
    out
}

fn fmt_amount(v: Option<f64>) -> String {
    match v {
        Some(x) if x.abs() >= 1.0 => format!("{x:.6}"),
        Some(x) => format!("{x:.10}"),
        None => "?".to_string(),
    }
}

fn fmt_usd(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("${x:.2}"),
        None => "?".to_string(),
    }
}

fn print_priced_totals(totals: &[PricedTotal]) {
    let rows: Vec<Vec<String>> = totals
        .iter()
        .map(|t| {
            vec![
                t.ticker.clone().unwrap_or_else(|| "?".to_string()),
                t.mint.clone(),
                t.decimals.map(|d| d.to_string()).unwrap_or_else(|| "?".to_string()),
                t.n_notes.to_string(),
                t.raw.to_string(),
                fmt_amount(t.decimal_amount),
                fmt_usd(t.price_usd),
                fmt_usd(t.usd_value),
            ]
        })
        .collect();
    print_table(
        &["ticker", "mint", "dec", "n_notes", "raw_total", "amount", "price", "value(USD)"],
        &rows,
    );
}

// --- Display ---------------------------------------------------------------

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let pad = |s: &str, w: usize| format!("{:<w$}", s, w = w);
    println!(
        "  {}",
        headers.iter().enumerate().map(|(i, h)| pad(h, widths[i])).collect::<Vec<_>>().join("  ")
    );
    println!("  {}", widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("  "));
    for row in rows {
        println!(
            "  {}",
            row.iter()
                .enumerate()
                .map(|(i, c)| pad(c, widths.get(i).copied().unwrap_or(c.len())))
                .collect::<Vec<_>>()
                .join("  ")
        );
    }
}

fn print_fees(fees: &[Fee], token_index: &TokenIndex, limit: usize) {
    let shown = fees.len().min(limit);
    let rows: Vec<Vec<String>> = fees
        .iter()
        .take(shown)
        .map(|f| {
            let info = token_index.get(&f.mint.to_lowercase());
            let ticker = info.map(|t| t.ticker.clone()).unwrap_or_else(|| "?".to_string());
            let decimals = info.map(|t| t.decimals);
            let amount = decimals
                .map(|d| (f.amount_raw as f64) / 10f64.powi(d as i32))
                .map(|a| {
                    if a.abs() >= 1.0 {
                        format!("{a:.6}")
                    } else {
                        format!("{a:.10}")
                    }
                })
                .unwrap_or_else(|| "?".to_string());
            vec![
                f.id.to_string(),
                ticker,
                f.amount_raw.to_string(),
                amount,
                truncate(&f.tx_hash, 14),
                truncate(&f.receiver, 18),
            ]
        })
        .collect();
    print_table(&["id", "ticker", "raw", "amount", "tx_hash", "receiver"], &rows);
    if shown < fees.len() {
        println!("  ... {} more row(s) suppressed (pass --all to dump everything)", fees.len() - shown);
    }
}

fn print_wallets(wallets: &[FeeWallet]) {
    let rows: Vec<Vec<String>> = wallets
        .iter()
        .map(|w| {
            let mints_str = w
                .mints
                .iter()
                .map(|m| m.as_deref().unwrap_or("<null>").to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mints_disp = if mints_str.is_empty() { "(empty)".to_string() } else { mints_str };
            vec![w.id.to_string(), mints_disp, w.secret_id.clone()]
        })
        .collect();
    print_table(&["wallet_id", "mints", "secret_id"], &rows);
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

// --- reconstruct-wallet (Phase 1) ------------------------------------------

async fn run_reconstruct_wallet(
    args: ReconstructWalletArgs,
    aws_region: &str,
    db_url: &str,
) -> Result<()> {
    let chain = args.chain;

    // 1. Resolve the list of wallets to process.
    let wallet_ids: Vec<Uuid> = match args.wallet_id {
        Some(uuid) => vec![uuid],
        None => {
            let pg = connect_pg(db_url).await?;
            let wallets = load_fee_wallets(&pg, chain.db_value()).await?;
            if wallets.is_empty() {
                return Err(eyre!(
                    "no fee-redemption wallets found in the DB for chain={}; \
                     run `inspect --chain {}` to confirm",
                    chain.display_name(),
                    chain.display_name()
                ));
            }
            println!(
                "found {} fee wallet(s) for {} (no --wallet-id specified, processing all)",
                wallets.len(),
                chain.display_name()
            );
            wallets.into_iter().map(|w| w.id).collect()
        }
    };

    // 2. Resolve the RPC URL once (shared across all wallets if walking).
    let rpc_url = if args.no_walk {
        String::new()
    } else {
        resolve_rpc_url(&args.rpc_url, chain, aws_region).await?
    };

    // 3. Load token-mappings + build a shared HTTP client for pricing.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .wrap_err("building reqwest client")?;
    let token_index = fetch_token_index(&http, &args.token_mappings_base_url, chain)
        .await
        .wrap_err_with(|| format!("loading token mappings for {}", chain.display_name()))?;

    // 3a. Resolve the checkpoint config.
    let checkpoint_dir = args.checkpoint_dir.clone().unwrap_or_else(default_checkpoint_dir);
    let checkpoint_cfg = CheckpointCfg {
        dir: checkpoint_dir.clone(),
        every: args.checkpoint_every.max(1),
        from_scratch: args.from_scratch,
    };
    if !args.no_walk {
        println!(
            "checkpoint dir: {checkpoint_dir} (every {} updates{})",
            checkpoint_cfg.every,
            if checkpoint_cfg.from_scratch { ", IGNORING existing checkpoints" } else { "" }
        );
    }

    // 4. Process each wallet sequentially. Track per-wallet USD totals so we
    //    can print a chain-wide grand total at the end.
    let mut had_error = false;
    let mut chain_total_usd: f64 = 0.0;
    let mut chain_unknown_rows: usize = 0;
    for (idx, wallet_id) in wallet_ids.iter().enumerate() {
        println!(
            "\n################################################################\n# wallet {} of {}: {wallet_id}\n################################################################",
            idx + 1,
            wallet_ids.len(),
        );
        match reconstruct_one_wallet(
            chain,
            *wallet_id,
            aws_region,
            &rpc_url,
            args.no_walk,
            &http,
            &args.price_reporter_url,
            &token_index,
            &checkpoint_cfg,
        )
        .await
        {
            Ok(Some(t)) => {
                chain_total_usd += t.total_usd;
                chain_unknown_rows += t.unknown_rows;
            }
            Ok(None) => {}
            Err(e) => {
                had_error = true;
                eprintln!("[{wallet_id}] ERROR: {e:#}");
            }
        }
    }

    if !args.no_walk && wallet_ids.len() > 1 {
        println!("\n================================================================");
        println!("CHAIN TOTAL ({}, across {} wallet(s))", chain.display_name(), wallet_ids.len());
        if chain_unknown_rows == 0 {
            println!("  fee-wallet balances: ${chain_total_usd:.2}");
        } else {
            println!(
                "  fee-wallet balances: ${chain_total_usd:.2} ({chain_unknown_rows} row(s) excluded — missing ticker, decimals, or price)"
            );
        }
        println!("================================================================");
    }

    if had_error {
        std::process::exit(1);
    }
    Ok(())
}

/// Per-wallet pricing summary returned by `reconstruct_one_wallet`. `None`
/// is returned when the walk was skipped (`--no-walk`) so we don't roll a
/// zero into the chain total.
struct WalletTotal {
    total_usd: f64,
    unknown_rows: usize,
}

async fn reconstruct_one_wallet(
    chain: ChainArg,
    wallet_id: Uuid,
    aws_region: &str,
    rpc_url: &str,
    no_walk: bool,
    http: &reqwest::Client,
    price_reporter_url: &str,
    token_index: &TokenIndex,
    checkpoint_cfg: &CheckpointCfg,
) -> Result<Option<WalletTotal>> {
    use alloy::signers::local::PrivateKeySigner;
    use common::types::wallet::{
        Wallet,
        derivation::{
            derive_blinder_seed, derive_share_seed, derive_wallet_id, derive_wallet_keychain,
        },
    };

    let secret_name = format!("{}/redemption-wallet-{}", chain.secret_prefix(), wallet_id);
    let chain_id = chain.chain_id();

    println!("  chain:        {}", chain.display_name());
    println!("  wallet_id:    {wallet_id}");
    println!("  secret:       {secret_name}");
    println!("  chain_id:     {chain_id}");

    // 1. Pull the eth root key from AWS Secrets Manager.
    let eth_key_hex = fetch_secret(aws_region, &secret_name).await?;
    let eth_key: PrivateKeySigner = eth_key_hex
        .parse()
        .map_err(|e| eyre!("parsing PrivateKeySigner from secret: {e}"))?;

    // 2. Derive deterministic params.
    let derived_wallet_id =
        derive_wallet_id(&eth_key).map_err(|e| eyre!("derive_wallet_id: {e}"))?;
    let blinder_seed =
        derive_blinder_seed(&eth_key).map_err(|e| eyre!("derive_blinder_seed: {e}"))?;
    let share_seed =
        derive_share_seed(&eth_key).map_err(|e| eyre!("derive_share_seed: {e}"))?;
    let keychain = derive_wallet_keychain(&eth_key, chain_id)
        .map_err(|e| eyre!("derive_wallet_keychain: {e}"))?;

    if derived_wallet_id != wallet_id {
        return Err(eyre!(
            "derived wallet_id ({derived_wallet_id}) != DB wallet_id ({wallet_id}); \
             secret is for the wrong wallet, or chain_id is wrong"
        ));
    }
    println!("  derive_wallet_id ✓ matches DB wallet_id");
    println!("  blinder_seed     = 0x{}", scalar_hex(&blinder_seed));
    println!("  share_seed       = 0x{}", scalar_hex(&share_seed));

    let mut wallet = Wallet::new_empty_wallet(wallet_id, blinder_seed, share_seed, keychain);
    println!(
        "  genesis pub_blinder = 0x{}",
        scalar_hex(&wallet.public_blinder())
    );

    if no_walk {
        println!("  (skipping on-chain walk: --no-walk set)");
        return Ok(None);
    }

    let summary = walk_chain(chain, rpc_url, &mut wallet, wallet_id, checkpoint_cfg).await?;
    println!("\n  on-chain walk:");
    println!("    updates applied:  {}", summary.n_updates);
    println!("    first tx:         {}", summary.first_tx);
    println!("    first tx block:   {}", summary.first_block);
    println!("    last tx:          {}", summary.last_tx);
    println!("    last tx block:    {}", summary.last_block);
    println!("    final blinder:    0x{}", scalar_hex(&wallet.blinder));
    println!(
        "    next pub blinder: 0x{}",
        scalar_hex(&wallet.next_public_blinder())
    );

    // Price every nonzero balance via the price reporter.
    let mints: Vec<String> = wallet
        .balances
        .values()
        .filter(|b| b.amount > 0)
        .map(|b| format!("0x{:040x}", b.mint))
        .collect();
    let prices = fetch_prices(http, price_reporter_url, token_index, mints).await;

    println!("\n  current wallet balances:");
    let total = print_wallet_balances_priced(&wallet, token_index, &prices);
    Ok(Some(total))
}

#[derive(Debug, Clone, Default)]
struct WalkSummary {
    n_updates: usize,
    first_tx: String,
    first_block: u64,
    last_tx: String,
    last_block: u64,
}

/// V1 darkpool proxy addresses. Mirror `funds-manager-server/src/helpers.rs:
/// {ARBITRUM_ONE,BASE_MAINNET}_DARKPOOL_ADDRESS`.
const ARB1_PROXY_ADDR_STR: &str = "0x30bD8eAb29181F790D7e495786d4B96d7AfDC518";
const BASE_MAINNET_PROXY_ADDR_STR: &str = "0xb4a96068577141749CC8859f586fE29016C935dB";

fn proxy_for(chain: ChainArg) -> alloy_primitives::Address {
    let s = match chain {
        ChainArg::ArbitrumOne => ARB1_PROXY_ADDR_STR,
        ChainArg::BaseMainnet => BASE_MAINNET_PROXY_ADDR_STR,
    };
    s.parse().expect("hardcoded proxy address parse")
}

async fn walk_chain(
    chain: ChainArg,
    rpc_url: &str,
    wallet: &mut common::types::wallet::Wallet,
    wallet_id: Uuid,
    cfg: &CheckpointCfg,
) -> Result<WalkSummary> {
    use alloy::providers::{Provider, ProviderBuilder};
    use std::time::Instant;

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().wrap_err("--rpc-url")?);
    let proxy = proxy_for(chain);
    let latest = provider.get_block_number().await.wrap_err("eth_blockNumber")?;

    let ckpt_path = checkpoint_path(&cfg.dir, chain, wallet_id);
    let mut summary = WalkSummary::default();
    let mut from_block: u64 = 0;

    // --- Try resuming from checkpoint --- //
    if !cfg.from_scratch {
        match Checkpoint::load(&ckpt_path) {
            Some(ckpt) if ckpt.chain == chain.display_name() && ckpt.wallet_id == wallet_id => {
                wallet.update_from_shares(&ckpt.private_shares, &ckpt.blinded_public_shares);
                summary.first_block = ckpt.first_block;
                summary.first_tx = ckpt.first_tx;
                summary.last_block = ckpt.last_block;
                summary.last_tx = ckpt.last_tx;
                summary.n_updates = ckpt.n_updates;
                from_block = ckpt.last_block + 1;
                println!(
                    "  resumed from checkpoint: {} updates, last_block={}",
                    summary.n_updates, summary.last_block
                );
            }
            Some(other) => {
                eprintln!(
                    "  ignoring checkpoint at {}: chain/wallet mismatch (got chain={}, wallet={})",
                    ckpt_path.display(),
                    other.chain,
                    other.wallet_id
                );
            }
            None => {}
        }
    }

    // --- Genesis step (only if not resumed) --- //
    if summary.n_updates == 0 {
        let genesis_log = find_walletupdated_log(
            &provider,
            proxy,
            &wallet.public_blinder(),
            from_block,
            latest,
        )
        .await?
        .ok_or_else(|| {
            eyre!(
                "no WalletUpdated log for genesis public_blinder=0x{}; wallet was never \
                 written to {} (DB row may be a ghost row, or `new_wallet` tx is on a different chain)",
                scalar_hex(&wallet.public_blinder()),
                chain.display_name()
            )
        })?;

        apply_genesis_update(chain, &provider, wallet, &genesis_log).await?;
        summary.first_block = genesis_log.block_number.unwrap_or(0);
        summary.first_tx = format_tx_hash(genesis_log.transaction_hash);
        summary.last_block = summary.first_block;
        summary.last_tx = summary.first_tx.clone();
        summary.n_updates = 1;
        from_block = summary.first_block + 1;
    }

    // --- Set up progress tracking --- //
    let progress = WalkProgress {
        start_time: Instant::now(),
        start_block: summary.last_block,
        start_n_updates: summary.n_updates,
        latest_block: latest,
    };

    // --- Forward walk --- //
    loop {
        let next_pub = wallet.next_public_blinder();
        let log = match find_walletupdated_log(&provider, proxy, &next_pub, from_block, latest)
            .await?
        {
            Some(l) => l,
            None => break,
        };
        apply_walk_update(chain, &provider, wallet, &log).await?;
        summary.n_updates += 1;
        summary.last_block = log.block_number.unwrap_or(summary.last_block);
        summary.last_tx = format_tx_hash(log.transaction_hash);
        from_block = summary.last_block + 1;

        if summary.n_updates % 50 == 0 {
            progress.log(&summary);
        }
        if summary.n_updates % cfg.every == 0 {
            if let Err(e) = Checkpoint::save(&ckpt_path, chain, wallet_id, wallet, &summary) {
                tracing::warn!("checkpoint save failed: {e:#}");
            }
        }
    }

    // Final checkpoint after the walk terminates — captures the resting state
    // so a re-run is a near no-op.
    if let Err(e) = Checkpoint::save(&ckpt_path, chain, wallet_id, wallet, &summary) {
        tracing::warn!("final checkpoint save failed: {e:#}");
    }

    Ok(summary)
}

/// Genesis step: the `new_wallet` tx. Verify the on-chain public shares
/// match what `Wallet::new_empty_wallet` produced from the derived seeds;
/// no state update needed (the local wallet already matches).
async fn apply_genesis_update(
    chain: ChainArg,
    provider: &impl alloy::providers::Provider,
    wallet: &mut common::types::wallet::Wallet,
    log: &alloy::rpc::types::Log,
) -> Result<()> {
    let (selector, calldata, tx_hash) = fetch_calldata(provider, log).await?;
    let target_pub_blinder = wallet.public_blinder();
    let decoded_public_shares = parse_shares(chain, selector, &calldata, target_pub_blinder)
        .wrap_err_with(|| {
            format!(
                "decoding shares from genesis tx {tx_hash} selector 0x{}",
                hex::encode(selector)
            )
        })?;

    if decoded_public_shares.blinder != wallet.public_blinder() {
        return Err(eyre!(
            "genesis tx public_blinder mismatch: chain=0x{} local=0x{}",
            scalar_hex(&decoded_public_shares.blinder),
            scalar_hex(&wallet.public_blinder())
        ));
    }
    // Apply with current private_shares to refresh derived balance/order
    // state. For an empty new_wallet this is a no-op on balances.
    let private_shares = wallet.private_shares.clone();
    wallet.update_from_shares(&private_shares, &decoded_public_shares);
    Ok(())
}

/// Subsequent walk step: predict next private_shares via hash chain, decode
/// new public_shares from the tx, apply.
async fn apply_walk_update(
    chain: ChainArg,
    provider: &impl alloy::providers::Provider,
    wallet: &mut common::types::wallet::Wallet,
    log: &alloy::rpc::types::Log,
) -> Result<()> {
    use circuit_types::SizedWalletShare;
    use circuit_types::traits::BaseType;
    use renegade_crypto::hash::evaluate_hash_chain;

    let (selector, calldata, tx_hash) = fetch_calldata(provider, log).await?;
    let target_pub_blinder = wallet.next_public_blinder();
    let new_public_shares = parse_shares(chain, selector, &calldata, target_pub_blinder)
        .wrap_err_with(|| {
            format!(
                "decoding shares from tx {tx_hash} selector 0x{}",
                hex::encode(selector)
            )
        })?;

    // Predict the next private shares — same hash-chain math as
    // `Wallet::reblind_wallet` in common/src/types/wallet/shares.rs.
    let scalars = wallet.private_shares.to_scalars();
    let n_shares = scalars.len();
    let chained = evaluate_hash_chain(wallet.private_shares.blinder, 2);
    let new_blinder_private = chained[1];
    let mut new_private = evaluate_hash_chain(scalars[n_shares - 2], n_shares - 1);
    new_private.push(new_blinder_private);
    let new_private_shares =
        SizedWalletShare::from_scalars(&mut new_private.into_iter());

    wallet.update_from_shares(&new_private_shares, &new_public_shares);
    Ok(())
}

async fn fetch_calldata(
    provider: &impl alloy::providers::Provider,
    log: &alloy::rpc::types::Log,
) -> Result<([u8; 4], Vec<u8>, alloy_primitives::B256)> {
    let tx_hash = log
        .transaction_hash
        .ok_or_else(|| eyre!("WalletUpdated log missing tx hash"))?;
    let tx = provider
        .get_transaction_by_hash(tx_hash)
        .await
        .wrap_err("eth_getTransactionByHash")?
        .ok_or_else(|| eyre!("tx {tx_hash} not found"))?;
    let calldata: Vec<u8> = alloy::consensus::Transaction::input(&tx).to_vec();
    if calldata.len() < 4 {
        return Err(eyre!("tx {tx_hash} has <4 calldata bytes"));
    }
    let selector: [u8; 4] = calldata[..4].try_into().unwrap();
    Ok((selector, calldata, tx_hash))
}

fn parse_shares(
    chain: ChainArg,
    selector: [u8; 4],
    calldata: &[u8],
    public_blinder_share: constants::Scalar,
) -> Result<circuit_types::SizedWalletShare> {
    match chain {
        ChainArg::ArbitrumOne => arb_parse_shares(selector, calldata, public_blinder_share),
        ChainArg::BaseMainnet => base_parse_shares(selector, calldata, public_blinder_share),
    }
}

fn arb_parse_shares(
    selector: [u8; 4],
    calldata: &[u8],
    public_blinder_share: constants::Scalar,
) -> Result<circuit_types::SizedWalletShare> {
    use darkpool_client::arbitrum::abi::{
        NEW_WALLET_SELECTOR, PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR,
        PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR,
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
        PROCESS_MATCH_SETTLE_SELECTOR, REDEEM_FEE_SELECTOR, SETTLE_OFFLINE_FEE_SELECTOR,
        SETTLE_ONLINE_RELAYER_FEE_SELECTOR, UPDATE_WALLET_SELECTOR,
    };
    use darkpool_client::arbitrum::helpers as arb;
    match selector {
        NEW_WALLET_SELECTOR => Ok(arb::parse_shares_from_new_wallet(calldata)?),
        UPDATE_WALLET_SELECTOR => Ok(arb::parse_shares_from_update_wallet(calldata)?),
        PROCESS_MATCH_SETTLE_SELECTOR => Ok(arb::parse_shares_from_process_match_settle(
            calldata,
            public_blinder_share,
        )?),
        PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR => {
            Ok(arb::parse_shares_from_process_atomic_match_settle(calldata)?)
        }
        PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
            Ok(arb::parse_shares_from_process_atomic_match_settle_with_receiver(calldata)?)
        }
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR => {
            Ok(arb::parse_shares_from_process_malleable_atomic_match_settle(calldata)?)
        }
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR => {
            Ok(arb::parse_shares_from_process_malleable_atomic_match_settle_with_receiver(
                calldata,
            )?)
        }
        SETTLE_ONLINE_RELAYER_FEE_SELECTOR => Ok(arb::parse_shares_from_settle_online_relayer_fee(
            calldata,
            public_blinder_share,
        )?),
        SETTLE_OFFLINE_FEE_SELECTOR => Ok(arb::parse_shares_from_settle_offline_fee(calldata)?),
        REDEEM_FEE_SELECTOR => Ok(arb::parse_shares_from_redeem_fee(calldata)?),
        other => Err(eyre!(
            "[arbitrum] unknown function selector 0x{}; tx likely went through a wrapper \
             contract (gas sponsor, CoW Protocol settle, ERC-4337 entrypoint). Add a \
             debug_trace fallback if this comes up in practice.",
            hex::encode(other)
        )),
    }
}

fn base_parse_shares(
    selector: [u8; 4],
    calldata: &[u8],
    public_blinder_share: constants::Scalar,
) -> Result<circuit_types::SizedWalletShare> {
    // Base v1 has a smaller surface than arbitrum: no `*_with_receiver`
    // variants, no `settleOnlineRelayerFee`. See base/mod.rs KNOWN_SELECTORS.
    use darkpool_client::base::abi::{
        NEW_WALLET_SELECTOR, PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR,
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR, PROCESS_MATCH_SETTLE_SELECTOR,
        REDEEM_FEE_SELECTOR, SETTLE_OFFLINE_FEE_SELECTOR, UPDATE_WALLET_SELECTOR,
    };
    use darkpool_client::base::helpers as base;
    match selector {
        NEW_WALLET_SELECTOR => Ok(base::parse_shares_from_new_wallet(calldata)?),
        UPDATE_WALLET_SELECTOR => Ok(base::parse_shares_from_update_wallet(calldata)?),
        PROCESS_MATCH_SETTLE_SELECTOR => Ok(base::parse_shares_from_process_match_settle(
            calldata,
            public_blinder_share,
        )?),
        PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR => {
            Ok(base::parse_shares_from_process_atomic_match_settle(calldata)?)
        }
        PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR => {
            Ok(base::parse_shares_from_process_malleable_atomic_match_settle(calldata)?)
        }
        SETTLE_OFFLINE_FEE_SELECTOR => Ok(base::parse_shares_from_settle_offline_fee(calldata)?),
        REDEEM_FEE_SELECTOR => Ok(base::parse_shares_from_redeem_fee(calldata)?),
        other => Err(eyre!(
            "[base] unknown function selector 0x{}; tx likely went through a wrapper \
             contract. Add a debug_trace fallback if this comes up in practice.",
            hex::encode(other)
        )),
    }
}

fn wallet_updated_topic0() -> alloy_primitives::B256 {
    alloy_primitives::keccak256(b"WalletUpdated(uint256)")
}

fn scalar_to_b256(s: &constants::Scalar) -> alloy_primitives::B256 {
    let big = renegade_crypto::fields::scalar_to_biguint(s);
    let mut bytes = big.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend(bytes);
        bytes = padded;
    } else if bytes.len() > 32 {
        bytes = bytes[bytes.len() - 32..].to_vec();
    }
    alloy_primitives::B256::from_slice(&bytes)
}

async fn find_walletupdated_log(
    provider: &impl alloy::providers::Provider,
    proxy: alloy_primitives::Address,
    public_blinder: &constants::Scalar,
    from_block: u64,
    to_block: u64,
) -> Result<Option<alloy::rpc::types::Log>> {
    let filter = alloy::rpc::types::Filter::new()
        .address(proxy)
        .event_signature(wallet_updated_topic0())
        .topic1(scalar_to_b256(public_blinder))
        .from_block(from_block)
        .to_block(to_block);
    let logs = provider.get_logs(&filter).await.wrap_err("eth_getLogs")?;
    Ok(logs.into_iter().next())
}

fn format_tx_hash(h: Option<alloy_primitives::B256>) -> String {
    h.map(|t| format!("0x{}", hex::encode(t))).unwrap_or_default()
}

/// Print the wallet's nonzero balances priced via the price reporter, and
/// return a per-wallet USD total + a count of rows that couldn't be priced
/// (so the chain-level summary knows whether to disclose exclusions).
fn print_wallet_balances_priced(
    wallet: &common::types::wallet::Wallet,
    token_index: &TokenIndex,
    prices: &PriceMap,
) -> WalletTotal {
    let nonzero: Vec<&circuit_types::balance::Balance> =
        wallet.balances.values().filter(|b| b.amount > 0).collect();
    if nonzero.is_empty() {
        println!("    (all balances zero)");
        return WalletTotal { total_usd: 0.0, unknown_rows: 0 };
    }

    // Build rows sorted by USD value desc, unknowns last (parallels
    // print_priced_totals in `inspect`).
    struct Row {
        ticker: String,
        mint: String,
        raw: u128,
        decimals: Option<u32>,
        price_usd: Option<f64>,
        decimal_amount: Option<f64>,
        usd_value: Option<f64>,
    }

    let mut rows: Vec<Row> = nonzero
        .iter()
        .map(|b| {
            let mint = format!("0x{:040x}", b.mint);
            let mint_lc = mint.to_lowercase();
            let info = token_index.get(&mint_lc);
            let ticker = info.map(|t| t.ticker.clone()).unwrap_or_else(|| "?".to_string());
            let decimals = info.map(|t| t.decimals);
            let raw = b.amount;
            let price_usd = prices.get(&mint_lc).copied();
            let decimal_amount = decimals.map(|d| (raw as f64) / 10f64.powi(d as i32));
            let usd_value = match (decimal_amount, price_usd) {
                (Some(a), Some(p)) => Some(a * p),
                _ => None,
            };
            Row { ticker, mint, raw, decimals, price_usd, decimal_amount, usd_value }
        })
        .collect();
    rows.sort_by(|a, b| match (b.usd_value, a.usd_value) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.mint.cmp(&b.mint),
    });

    let formatted: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                r.ticker.clone(),
                r.mint.clone(),
                r.decimals.map(|d| d.to_string()).unwrap_or_else(|| "?".to_string()),
                r.raw.to_string(),
                fmt_amount(r.decimal_amount),
                fmt_usd(r.price_usd),
                fmt_usd(r.usd_value),
            ]
        })
        .collect();
    // Indent the table to match the wallet block.
    let table_rows: Vec<Vec<String>> = formatted
        .into_iter()
        .map(|r| std::iter::once("  ".to_string()).chain(r).collect())
        .collect();
    print_table(
        &["", "ticker", "mint", "dec", "raw", "amount", "price", "value(USD)"],
        &table_rows,
    );

    let total_usd: f64 = rows.iter().filter_map(|r| r.usd_value).sum();
    let unknown_rows = rows.iter().filter(|r| r.usd_value.is_none()).count();
    if unknown_rows == 0 {
        println!("    wallet total: ${total_usd:.2}");
    } else {
        println!(
            "    wallet total: ${total_usd:.2} ({unknown_rows} row(s) excluded — missing ticker, decimals, or price)"
        );
    }
    WalletTotal { total_usd, unknown_rows }
}

async fn resolve_rpc_url(explicit: &str, chain: ChainArg, aws_region: &str) -> Result<String> {
    if !explicit.is_empty() {
        return Ok(explicit.to_string());
    }
    let secret_name = format!("{}/rpc-url", chain.secret_prefix());
    let url = fetch_secret(aws_region, &secret_name)
        .await
        .wrap_err_with(|| format!("resolving RPC URL from AWS secret {secret_name}"))?;
    tracing::info!("resolved RPC URL from AWS secret {secret_name}");
    Ok(url)
}

async fn fetch_secret(aws_region: &str, secret_name: &str) -> Result<String> {
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(aws_region.to_string()))
        .load()
        .await;
    let client = aws_sdk_secretsmanager::Client::new(&cfg);
    let resp = client
        .get_secret_value()
        .secret_id(secret_name)
        .send()
        .await
        .wrap_err_with(|| format!("get_secret_value({secret_name})"))?;
    let secret = resp
        .secret_string()
        .ok_or_else(|| eyre!("secret {secret_name} has no SecretString"))?;
    Ok(secret.trim().to_string())
}

fn scalar_hex(s: &constants::Scalar) -> String {
    renegade_crypto::fields::scalar_to_biguint(s).to_str_radix(16)
}

// --- estimate-gas (Phase 1.3.5) --------------------------------------------

async fn run_estimate_gas(args: EstimateGasArgs, db_url: &str, aws_region: &str) -> Result<()> {
    use alloy::providers::{Provider, ProviderBuilder};

    // Both arb1 and base-mainnet are supported here — both are Nitro-style
    // rollups whose eth_gasPrice already folds L1 amortization in, and both
    // have a `<chain-prefix>/rpc-url` secret in the same format.
    let rpc_url = resolve_rpc_url(&args.rpc_url, args.chain, aws_region).await?;

    println!("================================================================");
    println!("redeem-v1-fees-onchain estimate-gas");
    println!("  chain:           {}", args.chain.display_name());
    println!("  price-reporter:  {}", args.price_reporter_url);
    println!("  gas/tx (L2):     {} (planning estimate; verify empirically)", args.gas_per_tx);
    println!("================================================================");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .wrap_err("building reqwest client")?;

    // 1. ETH price from the Renegade price reporter, via the chain's WETH mint.
    let token_index =
        fetch_token_index(&http, &args.token_mappings_base_url, args.chain).await?;
    let weth_mint = token_index
        .values()
        .find(|t| t.ticker.eq_ignore_ascii_case("WETH"))
        .map(|t| t.address.to_lowercase())
        .ok_or_else(|| eyre!("WETH mint not found in {} token-mappings", args.chain.display_name()))?;
    let eth_usd =
        fetch_price_http(&http, &args.price_reporter_url, &weth_mint).await.wrap_err_with(
            || format!("fetching WETH price from {}", args.price_reporter_url),
        )?;

    // 2. Arb1 L2 gas price via eth_gasPrice. On Nitro this folds L1 calldata
    //    amortization into the L2 effective price, so a single number works.
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().wrap_err("--rpc-url")?);
    let gas_price_wei = provider.get_gas_price().await.wrap_err("eth_gasPrice")?;
    let gas_price_gwei = (gas_price_wei as f64) / 1e9;

    // 3. Per-tx cost.
    let wei_per_tx = (gas_price_wei as f64) * (args.gas_per_tx as f64);
    let eth_per_tx = wei_per_tx / 1e18;
    let usd_per_tx = eth_per_tx * eth_usd;

    println!("\nlive prices:");
    println!("  ETH/USD (price reporter):   ${eth_usd:.2}");
    println!("  arb1 gas price (eth_gasPrice): {gas_price_gwei:.6} gwei");
    println!("  per-tx cost:                ${usd_per_tx:.4}");

    // 4. Look up the actual unredeemed-note count from the DB.
    let client = connect_pg(db_url).await?;
    let chain_db = args.chain.db_value();
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM fees WHERE chain = $1 AND redeemed = false",
            &[&chain_db],
        )
        .await
        .wrap_err("count unredeemed fees")?;
    let actual_notes: i64 = row.get(0);
    let mut sizes: Vec<u64> = args.sizes.clone();
    if actual_notes > 0 {
        sizes.push(actual_notes as u64);
    }
    sizes.sort();
    sizes.dedup();

    println!("\nprojected gas cost by note count:");
    let mut rows: Vec<Vec<String>> = Vec::new();
    for n in sizes {
        let total_usd = (n as f64) * usd_per_tx;
        let mut row = vec![n.to_string(), format!("${total_usd:.2}")];
        if let Some(value) = args.total_value_usd {
            let net = value - total_usd;
            let net_str = if net >= 0.0 {
                format!("+${net:.2}")
            } else {
                format!("-${:.2}", -net)
            };
            row.push(format!("${value:.2}"));
            row.push(net_str);
        }
        rows.push(row);
    }
    let headers: Vec<&str> = if args.total_value_usd.is_some() {
        vec!["notes", "gas_cost", "value(USD)", "net(USD)"]
    } else {
        vec!["notes", "gas_cost"]
    };
    print_table(&headers, &rows);

    // 5. Per-note breakeven.
    println!("\nbreakeven:");
    println!("  any note worth less than ${usd_per_tx:.4} is uneconomic to redeem individually.");
    println!("  filter notes by `amount * price >= ${:.4}` to ensure each redemption is net-positive.",
             2.0 * usd_per_tx);

    println!(
        "\n(Phase 1.3.5 estimate uses --gas-per-tx={} as a constant. Phase 2+ will measure",
        args.gas_per_tx
    );
    println!("actual gasUsed from historical redeem_fee receipts to tighten this number.)");

    Ok(())
}

// --- value-curve (Phase 1.5) -----------------------------------------------

async fn run_value_curve(args: ValueCurveArgs, db_url: &str, aws_region: &str) -> Result<()> {
    use alloy::providers::{Provider, ProviderBuilder};

    println!("================================================================");
    println!("redeem-v1-fees-onchain value-curve");
    println!("  chain:           {}", args.chain.display_name());
    println!("  price-reporter:  {}", args.price_reporter_url);
    println!("  gas/tx (L2):     {}", args.gas_per_tx);
    println!("================================================================");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .wrap_err("building reqwest client")?;

    // 1. Load unredeemed fees + token mappings.
    let pg = connect_pg(db_url).await?;
    let fees = load_unredeemed_fees(&pg, args.chain.db_value()).await?;
    if fees.is_empty() {
        println!("\nno unredeemed fees for this chain.");
        return Ok(());
    }
    let token_index = fetch_token_index(&http, &args.token_mappings_base_url, args.chain).await?;

    // 2. Fetch prices for every distinct mint.
    let mints: Vec<String> = {
        let mut s: Vec<String> = fees.iter().map(|f| f.mint.to_lowercase()).collect();
        s.sort();
        s.dedup();
        s
    };
    let prices = fetch_prices(&http, &args.price_reporter_url, &token_index, mints).await;

    // 3. Compute live per-tx gas cost in USD.
    let rpc_url = resolve_rpc_url(&args.rpc_url, args.chain, aws_region).await?;
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().wrap_err("rpc-url")?);
    let gas_price_wei = provider.get_gas_price().await.wrap_err("eth_gasPrice")?;
    let gas_price_gwei = (gas_price_wei as f64) / 1e9;
    let weth_mint = token_index
        .values()
        .find(|t| t.ticker.eq_ignore_ascii_case("WETH"))
        .map(|t| t.address.to_lowercase())
        .ok_or_else(|| eyre!("WETH mint not found in token-mappings for {}", args.chain.display_name()))?;
    let eth_usd = fetch_price_http(&http, &args.price_reporter_url, &weth_mint).await?;
    let usd_per_tx =
        (gas_price_wei as f64) * (args.gas_per_tx as f64) / 1e18 * eth_usd;

    println!("\nlive prices:");
    println!("  ETH/USD:                ${eth_usd:.2}");
    println!("  {} gas price:        {gas_price_gwei:.6} gwei", args.chain.display_name());
    println!("  per-tx cost:            ${usd_per_tx:.4}");

    // 4. Per-note USD value. Unpriceable notes are reported separately so the
    //    user can see how much value is being excluded.
    struct PricedNote {
        usd: f64,
    }
    let mut priced: Vec<PricedNote> = Vec::with_capacity(fees.len());
    let mut unpriced_count: usize = 0;
    let mut unpriced_raw_by_mint: std::collections::BTreeMap<String, u128> =
        std::collections::BTreeMap::new();
    for f in &fees {
        let mint_lc = f.mint.to_lowercase();
        let info = token_index.get(&mint_lc);
        let price = prices.get(&mint_lc).copied();
        match (info, price) {
            (Some(t), Some(p)) => {
                let usd = (f.amount_raw as f64) / 10f64.powi(t.decimals as i32) * p;
                priced.push(PricedNote { usd });
            }
            _ => {
                unpriced_count += 1;
                *unpriced_raw_by_mint.entry(f.mint.clone()).or_insert(0) += f.amount_raw;
            }
        }
    }
    priced.sort_by(|a, b| b.usd.partial_cmp(&a.usd).unwrap_or(std::cmp::Ordering::Equal));

    // 5. Cumulative table at requested milestones + the all-priceable total.
    let total_priceable = priced.len() as u64;
    let mut milestones = args.milestones.clone();
    milestones.push(total_priceable);
    milestones.retain(|n| *n > 0 && *n <= total_priceable);
    milestones.sort();
    milestones.dedup();

    let mut cum_gross: f64 = 0.0;
    let mut milestone_iter = milestones.into_iter().peekable();
    let mut curve_rows: Vec<Vec<String>> = Vec::new();
    let mut breakeven_idx: Option<usize> = None;
    for (i, note) in priced.iter().enumerate() {
        cum_gross += note.usd;
        let n = (i + 1) as u64;
        // First time the marginal note drops below per-tx cost: record rank.
        if breakeven_idx.is_none() && note.usd < usd_per_tx {
            breakeven_idx = Some(i); // optimal redeem count is `i` (i.e. ranks 1..=i)
        }
        if let Some(&next_ms) = milestone_iter.peek() {
            if n == next_ms {
                milestone_iter.next();
                let gas = (n as f64) * usd_per_tx;
                let net = cum_gross - gas;
                let ratio = if gas > 0.0 { cum_gross / gas } else { f64::INFINITY };
                curve_rows.push(vec![
                    n.to_string(),
                    format!("${cum_gross:.2}"),
                    format!("${gas:.2}"),
                    format!(
                        "{}${:.2}",
                        if net >= 0.0 { "+" } else { "-" },
                        net.abs()
                    ),
                    format!("{ratio:.2}x"),
                    format!("${:.4}", note.usd),
                ]);
            }
        }
    }
    println!("\ncumulative redemption value vs rank (sorted by per-note USD desc):");
    print_table(
        &["rank", "cum_gross", "cum_gas", "net", "value/gas", "marginal_note"],
        &curve_rows,
    );

    // 6. Breakeven summary.
    println!("\nbreakeven:");
    match breakeven_idx {
        None => {
            // Every note was above breakeven.
            let all_gas = (priced.len() as f64) * usd_per_tx;
            let all_net = cum_gross - all_gas;
            println!(
                "  every priceable note exceeds the per-tx gas cost. Redeem all {} for net ${all_net:.2}.",
                priced.len()
            );
        }
        Some(0) => {
            println!(
                "  every priceable note is worth less than ${usd_per_tx:.4} of gas; no rank is individually profitable."
            );
        }
        Some(idx) => {
            // Optimal N is `idx`: notes at ranks 1..=idx are individually profitable.
            let optimal_n = idx as u64;
            let optimal_gross: f64 = priced[..idx].iter().map(|n| n.usd).sum();
            let optimal_gas = (optimal_n as f64) * usd_per_tx;
            let optimal_net = optimal_gross - optimal_gas;
            println!(
                "  marginal note drops below ${usd_per_tx:.4} at rank {}.",
                idx + 1
            );
            println!(
                "  redeeming the top {} notes captures ${optimal_gross:.2} at ${optimal_gas:.2} gas → net ${optimal_net:.2}",
                optimal_n
            );
        }
    }

    // 7. Unpriceable disclosure.
    if unpriced_count > 0 {
        println!(
            "\nunpriceable: {} note(s) across {} mint(s) had no ticker/decimals/price and were excluded from the curve.",
            unpriced_count,
            unpriced_raw_by_mint.len()
        );
        let rows: Vec<Vec<String>> = unpriced_raw_by_mint
            .iter()
            .map(|(mint, raw)| vec![mint.clone(), raw.to_string()])
            .collect();
        print_table(&["mint", "total_raw"], &rows);
    }

    Ok(())
}

// --- Checkpointing + ETA ---------------------------------------------------

struct CheckpointCfg {
    /// Directory where per-(chain, wallet_id) checkpoint files live.
    dir: String,
    /// Save a checkpoint every N applied updates.
    every: usize,
    /// Ignore existing checkpoints, walk from genesis.
    from_scratch: bool,
}

fn default_checkpoint_dir() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{home}/.cache/redeem-v1-fees-onchain")
}

fn checkpoint_path(dir: &str, chain: ChainArg, wallet_id: Uuid) -> std::path::PathBuf {
    std::path::PathBuf::from(dir).join(format!("{}-{wallet_id}.json", chain.display_name()))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Checkpoint {
    /// Chain display name (e.g. "arbitrum-one"). Used to refuse loading a
    /// checkpoint into the wrong chain by mistake.
    chain: String,
    /// Wallet UUID. Same sanity-check purpose.
    wallet_id: Uuid,
    /// The current private shares of the wallet.
    private_shares: circuit_types::SizedWalletShare,
    /// The current blinded public shares of the wallet.
    blinded_public_shares: circuit_types::SizedWalletShare,
    /// Walk metadata.
    n_updates: usize,
    first_block: u64,
    first_tx: String,
    last_block: u64,
    last_tx: String,
}

impl Checkpoint {
    fn save(
        path: &std::path::Path,
        chain: ChainArg,
        wallet_id: Uuid,
        wallet: &common::types::wallet::Wallet,
        summary: &WalkSummary,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).wrap_err_with(|| {
                format!("creating checkpoint dir {}", parent.display())
            })?;
        }
        let ckpt = Checkpoint {
            chain: chain.display_name().to_string(),
            wallet_id,
            private_shares: wallet.private_shares.clone(),
            blinded_public_shares: wallet.blinded_public_shares.clone(),
            n_updates: summary.n_updates,
            first_block: summary.first_block,
            first_tx: summary.first_tx.clone(),
            last_block: summary.last_block,
            last_tx: summary.last_tx.clone(),
        };
        // Write atomically: write to <path>.tmp then rename.
        let tmp = path.with_extension("json.tmp");
        {
            let f = std::fs::File::create(&tmp)
                .wrap_err_with(|| format!("create {}", tmp.display()))?;
            serde_json::to_writer(f, &ckpt).wrap_err("serialize checkpoint")?;
        }
        std::fs::rename(&tmp, path).wrap_err_with(|| {
            format!("rename {} -> {}", tmp.display(), path.display())
        })?;
        Ok(())
    }

    fn load(path: &std::path::Path) -> Option<Self> {
        let f = std::fs::File::open(path).ok()?;
        serde_json::from_reader(f).ok()
    }
}

/// Progress accounting for ETA display. Tracks the wall-clock start of THIS
/// run (i.e. since we resumed or since genesis), not the cumulative time
/// across resumed runs.
struct WalkProgress {
    start_time: std::time::Instant,
    /// Block we were at when this run started (after resume or genesis).
    start_block: u64,
    /// Update count we were at when this run started.
    start_n_updates: usize,
    /// Chain head at the start of this run.
    latest_block: u64,
}

impl WalkProgress {
    fn log(&self, summary: &WalkSummary) {
        let elapsed = self.start_time.elapsed();
        let blocks_done = summary.last_block.saturating_sub(self.start_block);
        let blocks_total = self.latest_block.saturating_sub(self.start_block);
        let pct = if blocks_total > 0 {
            (blocks_done as f64 / blocks_total as f64) * 100.0
        } else {
            100.0
        };
        let new_updates = summary.n_updates.saturating_sub(self.start_n_updates);
        let rate = if elapsed.as_secs_f64() > 0.0 {
            new_updates as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let eta = if blocks_done > 0 && blocks_total > blocks_done {
            let remaining = blocks_total - blocks_done;
            let secs_per_block = elapsed.as_secs_f64() / blocks_done as f64;
            let eta_secs = (remaining as f64 * secs_per_block) as u64;
            format_duration_secs(eta_secs)
        } else {
            "?".to_string()
        };
        tracing::info!(
            "walked {} updates (block {}/{}, {:.1}%, {:.1} upd/s, ETA {})",
            summary.n_updates,
            summary.last_block,
            self.latest_block,
            pct,
            rate,
            eta
        );
    }
}

fn format_duration_secs(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
