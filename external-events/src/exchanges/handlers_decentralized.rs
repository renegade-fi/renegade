use core::time::Duration;
use create2;
use futures::{executor::block_on, StreamExt};
use hex;
use ring_channel::RingSender;
use std::{
    cmp::Ordering,
    env,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
};
use web3::{
    self, ethabi,
    signing::keccak256,
    types::{BlockId, BlockNumber, H160, H256, U256},
    Web3,
};

use crate::{exchanges::connection::get_current_time, reporter::PriceReport, tokens::Token};

#[derive(Clone, Debug)]
pub struct UniswapV3Handler;
impl UniswapV3Handler {
    const FACTORY_ADDRESS: &str = "1f98431c8ad98523631ae4a59f267346ea31f984";
    const POOL_INIT_CODE_HASH: &str =
        "e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54";
    const ERC20_ABI: &str = r#"[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]"#;

    pub fn start_price_stream(
        base_token: Token,
        quote_token: Token,
        mut sender: RingSender<PriceReport>,
    ) {
        // Create the Web3 connection.
        let ethereum_wss_url = env::var("ETHEREUM_MAINNET_WSS").unwrap();
        let transport = block_on(web3::transports::WebSocket::new(&ethereum_wss_url)).unwrap();
        let web3_connection = Web3::new(transport);
        let web3_connection = Arc::new(Mutex::new(web3_connection));

        // Derive the Uniswap pool address from this Token pair.
        let (pool_address, is_flipped) =
            Self::get_pool_address(base_token, quote_token, web3_connection.clone()).unwrap();

        // Create a filter for Uniswap `Swap` events on this pool.
        let swap_event_abi = ethabi::Event {
            name: String::from("Swap"),
            inputs: vec![
                ethabi::EventParam {
                    name: String::from("sender"),
                    kind: ethabi::param_type::ParamType::Address,
                    indexed: true,
                },
                ethabi::EventParam {
                    name: String::from("recipient"),
                    kind: ethabi::param_type::ParamType::Address,
                    indexed: true,
                },
                ethabi::EventParam {
                    name: String::from("amount0"),
                    kind: ethabi::param_type::ParamType::Int(256),
                    indexed: false,
                },
                ethabi::EventParam {
                    name: String::from("amount1"),
                    kind: ethabi::param_type::ParamType::Int(256),
                    indexed: false,
                },
                ethabi::EventParam {
                    name: String::from("sqrtPriceX96"),
                    kind: ethabi::param_type::ParamType::Uint(160),
                    indexed: false,
                },
                ethabi::EventParam {
                    name: String::from("liquidity"),
                    kind: ethabi::param_type::ParamType::Uint(128),
                    indexed: false,
                },
                ethabi::EventParam {
                    name: String::from("tick"),
                    kind: ethabi::param_type::ParamType::Int(24),
                    indexed: false,
                },
            ],
            anonymous: false,
        };
        let swap_topic_filter = swap_event_abi
            .filter(ethabi::RawTopicFilter::default())
            .unwrap();
        let swap_filter_builder = web3::types::FilterBuilder::default()
            .address(vec![pool_address])
            .topic_filter(swap_topic_filter);

        let guard = web3_connection.lock().unwrap();
        let swap_filter = block_on(
            guard
                .eth_filter()
                .create_logs_filter(swap_filter_builder.build()),
        )
        .unwrap();

        let current_block = block_on(guard.eth().block_number()).unwrap();

        // Since it may be a while until we receive our first Swap event, we send the most recent
        // historic Swap as the current price.
        // TODO: Is there a better way to find the most recent Swap?
        let swap_filter_builder = swap_filter_builder
            .from_block(web3::types::BlockNumber::Number(current_block - 1000))
            .to_block(web3::types::BlockNumber::Latest);
        let swap_filter_recents = block_on(
            guard
                .eth_filter()
                .create_logs_filter(swap_filter_builder.build()),
        )
        .unwrap();
        drop(guard);

        // Process the most recent Swaps, then start streaming events from the swap_filter.
        let web3_connection_copy = web3_connection.clone();
        thread::spawn(move || {
            // Process the most recent Swap.
            let mut swap_filter_recent_events = block_on(swap_filter_recents.logs()).unwrap();
            swap_filter_recent_events.sort_by(|a, b| {
                if a.block_number < b.block_number {
                    return Ordering::Less;
                } else if a.block_number > b.block_number {
                    return Ordering::Greater;
                } else if a.transaction_index < b.transaction_index {
                    return Ordering::Greater;
                } else if a.transaction_index > b.transaction_index {
                    return Ordering::Less;
                }
                Ordering::Equal
            });
            let swap = swap_filter_recent_events.pop();
            if let Some(swap) = swap {
                let block_id = BlockId::Number(BlockNumber::Number(swap.block_number.unwrap()));
                let block_timestamp =
                    block_on(web3_connection.lock().unwrap().eth().block(block_id))
                        .unwrap()
                        .unwrap()
                        .timestamp;
                let price_report = Self::handle_event(swap, is_flipped, swap_event_abi.clone());
                if let Some(mut price_report) = price_report {
                    price_report.local_timestamp = get_current_time();
                    price_report.reported_timestamp = Some(block_timestamp.as_u128());
                    sender.send(price_report).unwrap();
                }
            }

            // Start streaming.
            let swap_stream = swap_filter.stream(Duration::new(1, 0));
            futures::pin_mut!(swap_stream);
            loop {
                let swap = block_on(swap_stream.next()).unwrap().unwrap();
                let block_id = BlockId::Number(BlockNumber::Number(swap.block_number.unwrap()));
                let block_timestamp =
                    block_on(web3_connection_copy.lock().unwrap().eth().block(block_id))
                        .unwrap()
                        .unwrap()
                        .timestamp;
                let price_report = Self::handle_event(swap, is_flipped, swap_event_abi.clone());
                if let Some(mut price_report) = price_report {
                    price_report.local_timestamp = get_current_time();
                    price_report.reported_timestamp = Some(block_timestamp.as_u128());
                    sender.send(price_report).unwrap();
                }
            }
        });
    }

    fn handle_event(
        swap: web3::types::Log,
        is_flipped: bool,
        swap_event_abi: web3::ethabi::Event,
    ) -> Option<PriceReport> {
        let swap = swap_event_abi
            .parse_log(ethabi::RawLog {
                topics: swap.topics.clone(),
                data: swap.data.clone().0,
            })
            .unwrap();
        // Extract the `sqrtPriceX96` and convert it to the marginal price of the Uniswapv3 pool,
        // as per: https://docs.uniswap.org/sdk/v3/guides/fetching-prices#understanding-sqrtprice
        let sqrt_price_x96 = &swap.params[4].value;
        let sqrt_price_x96 = match sqrt_price_x96 {
            ethabi::Token::Uint(sqrt_price_x96) => sqrt_price_x96,
            _ => unreachable!(),
        };
        let price_numerator = U256::from(sqrt_price_x96).pow(U256::from(2));
        let price_denominator = U256::from(2).pow(U256::from(192));
        let (price_numerator, price_denominator) = if is_flipped {
            (price_denominator, price_numerator)
        } else {
            (price_numerator, price_denominator)
        };
        // The best way to convert U256 to f64 is unfortunately to parse via Strings. Big L.
        let price_numerator: f64 = price_numerator.to_string().parse().unwrap();
        let price_denominator: f64 = price_denominator.to_string().parse().unwrap();
        // Note that this price does not adjust for ERC-20 decimals yet.
        let price = price_numerator / price_denominator;
        Some(PriceReport {
            midpoint_price: price as f64,
            reported_timestamp: None,
            local_timestamp: Default::default(),
        })
    }

    /// Given the base_token and quote_token, finds the address of the UniswapV3 pool with highest
    /// TVL among all fee tiers (1bp, 5bp, 30bp, 100bp). In addition, we return a boolean
    /// is_flipped that reflects whether the assets are flipped (i.e., quote per base) in the
    /// Uniswap pool.
    fn get_pool_address(
        base_token: Token,
        quote_token: Token,
        web3_connection: Arc<Mutex<Web3<web3::transports::WebSocket>>>,
    ) -> Option<(H160, bool)> {
        let base_token_addr = H160::from_str(base_token.get_addr()).unwrap();
        let quote_token_addr = H160::from_str(quote_token.get_addr()).unwrap();
        let is_flipped = base_token_addr > quote_token_addr;
        let (first_token, second_token) = if is_flipped {
            (quote_token_addr, base_token_addr)
        } else {
            (base_token_addr, quote_token_addr)
        };
        // Derive all pool addresses from the following fee tiers:
        // HIGH = 10000
        // MEDIUM = 3000
        // LOW = 500
        // LOWEST = 100
        let pool_addresses = [10_000_u32, 3000_u32, 500_u32, 100_u32].map(|fee_amt| {
            let mut fee = [0_u8; 32];
            fee[32 - 4..].clone_from_slice(&fee_amt.to_be_bytes());
            let pool_address = create2::calc_addr_with_hash(
                hex::decode(Self::FACTORY_ADDRESS).unwrap()[..20]
                    .try_into()
                    .unwrap(),
                &keccak256(
                    &[
                        H256::from(first_token).as_bytes(),
                        H256::from(second_token).as_bytes(),
                        &fee,
                    ]
                    .concat()[..],
                ),
                hex::decode(Self::POOL_INIT_CODE_HASH).unwrap()[..32]
                    .try_into()
                    .unwrap(),
            );
            H160::from(pool_address)
        });

        // Fetch the base balance from each pool address.
        let erc20_contract = ethabi::Contract::load(Self::ERC20_ABI.as_bytes()).unwrap();
        let base_balances = pool_addresses.map(|pool_address| {
            let mut base_balance_call_request = web3::types::CallRequest::default();
            base_balance_call_request.to = Some(web3::types::Address::from(base_token_addr));
            base_balance_call_request.data = Some(web3::types::Bytes(
                erc20_contract
                    .function("balanceOf")
                    .unwrap()
                    .encode_input(&[ethabi::token::Token::Address(pool_address)])
                    .unwrap(),
            ));
            let base_balance = block_on(
                web3_connection
                    .lock()
                    .unwrap()
                    .eth()
                    .call(base_balance_call_request, None),
            )
            .unwrap()
            .0;
            assert!(
                base_balance.len() == 32,
                "base_balance.len() = {}, expected 32.",
                base_balance.len()
            );
            U256::from(&base_balance[..32])
        });

        // Given the derived pool addresses and base balances, pick the pool address with the
        // highest base balance.
        let mut max_base_balance = U256::zero();
        let mut max_pool_idx: usize = 0;
        for i in 0..4 {
            if base_balances[i] > max_base_balance {
                max_base_balance = base_balances[i];
                max_pool_idx = i;
            }
        }
        Some((H160::from(pool_addresses[max_pool_idx]), is_flipped))
    }
}
