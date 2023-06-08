//! Defines logic for streaming from decentralized exchanges

use async_trait::async_trait;
use core::time::Duration;
use curve25519_dalek::digest::generic_array::typenum::Ord;
use futures::StreamExt;
use futures_util::Stream;
use std::{
    cmp::Ordering,
    convert::TryInto,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};
use tracing::log;
use web3::{
    self,
    api::BaseFilter,
    ethabi::{self, Event},
    signing::keccak256,
    transports::WebSocket as Web3Socket,
    types::{BlockNumber, FilterBuilder, Log as ContractLog, H160, H256, U256},
    Web3,
};

use crate::price_reporter::{reporter::Price, worker::PriceReporterManagerConfig};

use super::{
    super::{errors::ExchangeConnectionError, tokens::Token},
    ExchangeConnection, InitializablePriceStream,
};

// -------------
// | Constants |
// -------------

/// The start byte to pack a fee into
const FEE_START_BYTE: usize = 32 - 4;
/// The historical offset to query blocks in for the first swap
const BLOCK_OFFSET: u64 = 10_000;

/// The error message emitted when swap logs cannot be found for a UniV3 pool
const ERR_NO_LOGS: &str = "no swap logs found for asset pair";

lazy_static! {
    // The ABI for a UniswapV3 Swap event
    static ref SWAP_EVENT_ABI: ethabi::Event = {
        ethabi::Event {
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
        }
    };
}

/// The core handler for UniswapV3, responsible for defining Swap event filters, streaming events,
/// and parsing as PriceReports.
pub struct UniswapV3Connection {
    /// The underlying price stream
    price_stream: Box<dyn Stream<Item = Price> + Unpin + Send>,
}

impl UniswapV3Connection {
    /// The UniswapV3 factory address.
    const FACTORY_ADDRESS: &str = "1f98431c8ad98523631ae4a59f267346ea31f984";
    /// The UniswapV3 code hash. From:
    /// https://docs.uniswap.org/sdk/v3/reference/overview#pool_init_code_hash
    const POOL_INIT_CODE_HASH: &str =
        "e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54";
    /// The standard ERC-20 JSON ABI. From:
    /// https://gist.github.com/veox/8800debbf56e24718f9f483e1e40c35c
    const ERC20_ABI: &str = r#"[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]"#;

    /// Handles a Swap event log streamed from the web3 connection.
    ///
    /// `decimal_correction` is a multiplicative factor applied to the price to
    /// correct for ratio mismatch in ERC20 decimals
    fn midpoint_from_swap_event(
        swap: ContractLog,
        is_flipped: bool,
        decimal_correction: f64,
        swap_event_abi: &Event,
    ) -> Price {
        let swap = swap_event_abi
            .parse_log(ethabi::RawLog {
                topics: swap.topics,
                data: swap.data.0,
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

        // Note that this price does not adjust for ERC-20 decimals yet
        (price_numerator / price_denominator) * decimal_correction
    }

    /// Fetch an ad-hoc price report from the UniswapV3 pool, used for
    /// initializing a price stream
    async fn fetch_price_report(
        base_token: &Token,
        quote_token: &Token,
        decimal_correction: f64,
        web3_connection: &Web3<Web3Socket>,
    ) -> Result<Price, ExchangeConnectionError> {
        // Build a filter to fetch events from the last `BLOCK_OFFSET` blocks
        let current_block = web3_connection.eth().block_number().await.unwrap();
        let (swap_filter, is_flipped) = Self::create_swap_filter(
            base_token,
            quote_token,
            Some(BlockNumber::Number(current_block - BLOCK_OFFSET)),
            Some(BlockNumber::Number(current_block)),
            web3_connection,
        )
        .await?;

        // Process the most recent Swap
        let mut swap_filter_recent_events = swap_filter.logs().await.unwrap();
        swap_filter_recent_events.sort_by(|a, b| match a.block_number.cmp(&b.block_number) {
            // Same block resolves by transaction index
            Ordering::Equal => a.transaction_index.cmp(&b.transaction_index),
            ordering => ordering,
        });

        swap_filter_recent_events
            .pop()
            .ok_or_else(|| ExchangeConnectionError::NoLogs(ERR_NO_LOGS.to_string()))
            .map(|swap| {
                Self::midpoint_from_swap_event(
                    swap,
                    is_flipped,
                    decimal_correction,
                    &SWAP_EVENT_ABI,
                )
            })
    }

    /// Create an event filter for UniV3 swaps
    async fn create_swap_filter(
        base_token: &Token,
        quote_token: &Token,
        from_block: Option<BlockNumber>,
        to_block: Option<BlockNumber>,
        web3_connection: &Web3<Web3Socket>,
    ) -> Result<(BaseFilter<Web3Socket, ContractLog>, bool), ExchangeConnectionError> {
        // Derive the Uniswap pool address from this Token pair.
        let (pool_address, is_flipped) =
            Self::get_pool_address(base_token, quote_token, web3_connection).await?;

        // Build a filter for Uniswap Swap events
        let swap_event_abi = SWAP_EVENT_ABI.clone();
        let swap_topic_filter = swap_event_abi
            .filter(ethabi::RawTopicFilter::default())
            .unwrap();
        let mut swap_filter_builder = FilterBuilder::default()
            .address(vec![pool_address])
            .topic_filter(swap_topic_filter);

        // Add block constrains
        if let Some(block) = from_block {
            swap_filter_builder = swap_filter_builder.from_block(block);
        }

        if let Some(block) = to_block {
            swap_filter_builder = swap_filter_builder.to_block(block);
        }

        Ok((
            web3_connection
                .eth_filter()
                .create_logs_filter(swap_filter_builder.build())
                .await
                .unwrap(),
            is_flipped,
        ))
    }

    /// Given the base_token and quote_token, finds the address of the UniswapV3 pool with highest
    /// TVL among all fee tiers (1bp, 5bp, 30bp, 100bp). In addition, we return a boolean
    /// is_flipped that reflects whether the assets are flipped (i.e., quote per base) in the
    /// Uniswap pool
    async fn get_pool_address(
        base_token: &Token,
        quote_token: &Token,
        web3_connection: &Web3<Web3Socket>,
    ) -> Result<(H160, bool), ExchangeConnectionError> {
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
            fee[FEE_START_BYTE..].clone_from_slice(&fee_amt.to_be_bytes());

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

        // Fetch the base balance from each pool address
        let erc20_contract = ethabi::Contract::load(Self::ERC20_ABI.as_bytes()).unwrap();
        let mut base_balances = vec![];
        for pool_address in pool_addresses.iter() {
            let base_balance_call_request = web3::types::CallRequest::builder()
                .to(base_token_addr)
                .data(web3::types::Bytes(
                    erc20_contract
                        .function("balanceOf")
                        .unwrap()
                        .encode_input(&[ethabi::token::Token::Address(*pool_address)])
                        .unwrap(),
                ))
                .build();
            let base_balance = web3_connection
                .eth()
                .call(base_balance_call_request, None)
                .await
                .map(|base_balance| U256::from(&base_balance.0[..32]))
                .map_err(|err| ExchangeConnectionError::ConnectionHangup(err.to_string()))?;
            base_balances.push(base_balance);
        }

        // Given the derived pool addresses and base balances, pick the pool address with the
        // highest base balance
        let mut max_base_balance = U256::zero();
        let mut max_pool_idx: usize = 0;
        for (i, base_balance) in base_balances.into_iter().enumerate() {
            if base_balance > max_base_balance {
                max_base_balance = base_balance;
                max_pool_idx = i;
            }
        }

        Ok((pool_addresses[max_pool_idx], is_flipped))
    }
}

impl Stream for UniswapV3Connection {
    type Item = Price;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Pin::new(&mut this.price_stream).poll_next(cx)
    }
}

#[async_trait]
impl ExchangeConnection for UniswapV3Connection {
    /// Create a new connection to the exchange on a given asset pair
    async fn connect(
        base_token: Token,
        quote_token: Token,
        config: &PriceReporterManagerConfig,
    ) -> Result<Self, ExchangeConnectionError>
    where
        Self: Sized,
    {
        // Create the Web3 connection.
        let ethereum_wss_url = config.eth_websocket_addr.clone().unwrap();
        let transport = web3::transports::WebSocket::new(&ethereum_wss_url)
            .await
            .map_err(|err| ExchangeConnectionError::HandshakeFailure(err.to_string()))?;
        let web3_connection = Web3::new(transport);

        // If the tokens are named in UniswapV3, adjust the price by the ERC20
        // decimal ratio
        let decimal_adjustment = if base_token.is_named() && quote_token.is_named() {
            10f64.powi(
                base_token.get_decimals().unwrap() as i32
                    - quote_token.get_decimals().unwrap() as i32,
            )
        } else {
            1.
        };

        // Fetch an inital price report to setup the stream
        let initial_price_report = Self::fetch_price_report(
            &base_token,
            &quote_token,
            decimal_adjustment,
            &web3_connection,
        )
        .await?;

        // Create a filter for UniV3 swaps
        let (base_filter, is_flipped) = Self::create_swap_filter(
            &base_token,
            &quote_token,
            None, /* from_block */
            None, /* to_block */
            &web3_connection,
        )
        .await?;

        // Start streaming events from the swap_filter.
        let mapped_stream =
            base_filter
                .stream(Duration::new(1, 0))
                .filter_map(move |swap| async move {
                    match swap {
                        Ok(swap_event) => Some(Self::midpoint_from_swap_event(
                            swap_event,
                            is_flipped,
                            decimal_adjustment,
                            &SWAP_EVENT_ABI,
                        )),
                        Err(e) => {
                            log::error!("Error parsing Swap event from UniswapV3: {}", e);
                            None
                        }
                    }
                });

        // Build a price stream
        let price_stream = InitializablePriceStream::new_with_initial(
            Box::pin(mapped_stream),
            initial_price_report,
        );

        Ok(Self {
            price_stream: Box::new(price_stream),
        })
    }
}
