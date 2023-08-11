//! Utils related to declaring, deploying, and interacting with smart contracts in
//! the context of an integration test
//!
//! TODO: This should all be productionized and moved to the `starknet-client` crate

use constants::MERKLE_HEIGHT;
use eyre::{eyre, Result};
use reqwest::Url as ReqwestUrl;
use starknet::accounts::{Call, ConnectedAccount};
use starknet::contract::ContractFactory;
use starknet::core::chain_id;
use starknet::core::crypto::compute_hash_on_elements;
use starknet::core::types::{
    MaybePendingTransactionReceipt, TransactionReceipt, TransactionStatus,
};
use starknet::core::utils::get_selector_from_name;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use std::sync::Arc;
use std::time::Duration;
use std::{
    fs::File,
    path::{Path, PathBuf},
    str::FromStr,
};
use tracing::log;

use starknet::{
    accounts::{Account, SingleOwnerAccount},
    core::types::{
        contract::{CompiledClass, SierraClass},
        FieldElement,
    },
    signers::{LocalWallet, SigningKey},
};

// -------------
// | Constants |
// -------------

/// The file prefix for Darkpool compilation artifacts
pub const DARKPOOL_CONTRACT_NAME: &str = "renegade_contracts_Darkpool";
/// The file prefix for Merkle compilation artifacts
pub const MERKLE_CONTRACT_NAME: &str = "renegade_contracts_Merkle";
/// The file prefix for NullifierSet compilation artifacts
pub const NULLIFIER_SET_CONTRACT_NAME: &str = "renegade_contracts_NullifierSet";

/// The file extension that suffixes Sierra compilation artifacts
pub const SIERRA_FILE_EXTENSION: &str = "sierra.json";
/// The file extension that suffixes Cairo assembly (casm) compilation artifacts
pub const CASM_FILE_EXTENSION: &str = "casm.json";

/// The name of the initialize function
pub const INITIALIZE_FN_NAME: &str = "initialize";

/// Cairo string for "STARKNET_CONTRACT_ADDRESS"
const PREFIX_CONTRACT_ADDRESS: FieldElement = FieldElement::from_mont([
    3829237882463328880,
    17289941567720117366,
    8635008616843941496,
    533439743893157637,
]);

/// 2 ** 251 - 256
const ADDR_BOUND: FieldElement = FieldElement::from_mont([
    18446743986131443745,
    160989183,
    18446744073709255680,
    576459263475590224,
]);

/// The account type used to deploy contracts
pub type StarknetTestAcct = SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>;

// -----------
// | Helpers |
// -----------

/// Setup the darkpool contract and return its address
pub async fn deploy_darkpool(
    account_addr: &str,
    account_pkey: &str,
    cairo_artifacts_path: &str,
    devnet_url: &str,
) -> Result<FieldElement> {
    let deployer_account = build_deployer_acct(account_addr, account_pkey, devnet_url);

    // Declare the darkpool implementation
    log::info!("Declaring darkpool...");
    let (darkpool_sierra, darkpool_casm) =
        get_artifacts(cairo_artifacts_path, DARKPOOL_CONTRACT_NAME);
    let darkpool_hash = declare_class(&darkpool_sierra, &darkpool_casm, &deployer_account).await?;

    // Declare the Merkle implementation
    log::info!("Declaring merkle tree...");
    let (merkle_sierra, merkle_casm) = get_artifacts(cairo_artifacts_path, MERKLE_CONTRACT_NAME);
    let merkle_hash = declare_class(&merkle_sierra, &merkle_casm, &deployer_account).await?;

    // Declare the NullifierSet implementation
    log::info!("Declaring nullifier set...");
    let (nullifier_set_sierra, nullifier_set_casm) =
        get_artifacts(cairo_artifacts_path, NULLIFIER_SET_CONTRACT_NAME);
    let nullifier_set_hash = declare_class(
        &nullifier_set_sierra,
        &nullifier_set_casm,
        &deployer_account,
    )
    .await?;

    // Deploy the darkpool
    log::info!("Deploying darkpool...");
    let contract = ContractFactory::new(darkpool_hash, &deployer_account);
    let calldata = vec![deployer_account.address()];
    let deploy_tx = contract
        .deploy(
            calldata.clone(),
            FieldElement::ZERO, /* salt */
            false,              /* unique */
        )
        .send()
        .await?;
    await_transaction(deploy_tx.transaction_hash, &deployer_account).await?;
    let addr = calculate_contract_address(darkpool_hash, &calldata);

    // Initialize the contract
    log::info!("Initializing darkpool contract...");
    let init_calldata = vec![
        merkle_hash,
        nullifier_set_hash,
        FieldElement::from(MERKLE_HEIGHT),
    ];
    let res = deployer_account
        .execute(vec![Call {
            to: addr,
            selector: get_selector_from_name(INITIALIZE_FN_NAME)?,
            calldata: init_calldata.clone(),
        }])
        .send()
        .await?;
    await_transaction(res.transaction_hash, &deployer_account).await?;

    log::info!("Darkpool deployed at: {addr}");

    Ok(addr)
}

/// Build an account to deploy the contracts from
fn build_deployer_acct(
    account_addr: &str,
    account_pkey: &str,
    devnet_url: &str,
) -> StarknetTestAcct {
    // Create the API provider for the JSON-RPC API
    let rpc_url: ReqwestUrl = format!("{devnet_url}/rpc").parse().unwrap();
    let provider = JsonRpcClient::new(HttpTransport::new(rpc_url));

    let addr_felt = FieldElement::from_str(account_addr).unwrap();
    let pkey_felt = FieldElement::from_hex_be(account_pkey).unwrap();

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(pkey_felt));
    SingleOwnerAccount::new(provider, signer, addr_felt, chain_id::TESTNET)
}

/// Load the compilation artifacts for the given contract
///
/// Borrowed from: https://github.com/renegade-fi/renegade-contracts/blob/main/starknet_scripts/src/commands/utils.rs#L85
fn get_artifacts(artifacts_path: &str, contract_name: &str) -> (PathBuf, PathBuf) {
    let sierra_path = Path::new(artifacts_path)
        .join(contract_name)
        .with_extension(SIERRA_FILE_EXTENSION);
    let casm_path = Path::new(artifacts_path)
        .join(contract_name)
        .with_extension(CASM_FILE_EXTENSION);

    (sierra_path, casm_path)
}

/// Declare a contract class on the devnet
///
/// Borrowed from: https://github.com/renegade-fi/renegade-contracts/blob/main/starknet_scripts/src/commands/utils.rs#L114
async fn declare_class(
    sierra_source: &PathBuf,
    casm_source: &PathBuf,
    deployer: &StarknetTestAcct,
) -> Result<FieldElement> {
    // Read the source files into their runtime objects
    let sierra_contract: SierraClass = serde_json::from_reader(File::open(sierra_source)?)?;
    let flattened_class = sierra_contract.flatten()?;

    let casm_contract: CompiledClass = serde_json::from_reader(File::open(casm_source)?)?;
    let casm_class_hash = casm_contract.class_hash()?;

    let res = deployer
        .declare(Arc::new(flattened_class), casm_class_hash)
        .send()
        .await?;
    await_transaction(res.transaction_hash, deployer).await?;

    Ok(res.class_hash)
}

/// Taken from https://github.com/xJonathanLEI/starknet-rs/blob/master/starknet-accounts/src/factory/mod.rs
fn calculate_contract_address(
    class_hash: FieldElement,
    constructor_calldata: &[FieldElement],
) -> FieldElement {
    compute_hash_on_elements(&[
        PREFIX_CONTRACT_ADDRESS,
        FieldElement::ZERO, /* deployer address */
        FieldElement::ZERO, /* salt */
        class_hash,
        compute_hash_on_elements(constructor_calldata),
    ]) % ADDR_BOUND
}

/// Await a transaction to enter the `ACCEPTED ON L2` state
async fn await_transaction(tx_hash: FieldElement, rpc_client: &StarknetTestAcct) -> Result<()> {
    log::info!("Awaiting transaction {tx_hash:?}");
    loop {
        if let TransactionStatus::AcceptedOnL2 = get_transaction_status(tx_hash, rpc_client).await?
        {
            break;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

/// Get the status of a given transaction
async fn get_transaction_status(
    tx_hash: FieldElement,
    rpc_client: &StarknetTestAcct,
) -> Result<TransactionStatus> {
    let tx_receipt = rpc_client
        .provider()
        .get_transaction_receipt(tx_hash)
        .await?;
    let status = match tx_receipt {
        MaybePendingTransactionReceipt::PendingReceipt(receipt) => {
            return Err(eyre!("Transaction is still pending: {:?}", receipt));
        }
        MaybePendingTransactionReceipt::Receipt(receipt) => match receipt {
            TransactionReceipt::Invoke(tx) => tx.status,
            TransactionReceipt::Declare(tx) => tx.status,
            TransactionReceipt::Deploy(tx) => tx.status,
            _ => {
                return Err(eyre!(
                    "Transaction receipt is not an invoke, declare, or deploy receipt"
                ));
            }
        },
    };

    log::info!("transaction has status: {status:?}");
    Ok(status)
}
