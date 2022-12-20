use core::time::Duration;
use futures::{executor::block_on, StreamExt};
use ring_channel::RingSender;
use std::{str::FromStr, thread};
use web3::{
    self, ethabi,
    types::{BlockId, BlockNumber, H160, U256},
    Web3,
};

use crate::{exchanges::connection::get_current_time, reporter::PriceReport};

#[derive(Clone, Debug)]
pub struct UniswapV3Handler;
impl UniswapV3Handler {
    const WSS_URL: &'static str = "wss://mainnet.infura.io/ws/v3/68c04ec6f9ce42c5becbed52a464ef81";
    const ETH_USDC_ADDR: &'static str = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640";
    const BASE_DECIMALS: u8 = 18; /* i.e. WETH */
    const QUOTE_DECIMALS: u8 = 6; /* i.e. USDC */

    pub fn start_price_stream(mut sender: RingSender<PriceReport>) {
        let transport = block_on(web3::transports::WebSocket::new(Self::WSS_URL)).unwrap();
        let web3_connection = Web3::new(transport);
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
        let swap_filter = web3::types::FilterBuilder::default()
            .address(vec![H160::from_str(Self::ETH_USDC_ADDR).unwrap()])
            .topic_filter(swap_topic_filter)
            .build();
        let swap_filter =
            block_on(web3_connection.eth_filter().create_logs_filter(swap_filter)).unwrap();

        thread::spawn(move || {
            let swap_stream = swap_filter.stream(Duration::new(1, 0));
            futures::pin_mut!(swap_stream);
            loop {
                let swap = block_on(swap_stream.next()).unwrap().unwrap();
                let block_id = BlockId::Number(BlockNumber::Number(swap.block_number.unwrap()));
                let block_timestamp = block_on(web3_connection.eth().block(block_id))
                    .unwrap()
                    .unwrap()
                    .timestamp;
                let swap = swap_event_abi
                    .parse_log(ethabi::RawLog {
                        topics: swap.topics.clone(),
                        data: swap.data.clone().0,
                    })
                    .unwrap();
                let price_report = Self::handle_event(swap);
                if let Some(mut price_report) = price_report {
                    price_report.local_timestamp = get_current_time();
                    price_report.reported_timestamp = Some(block_timestamp.as_u128());
                    sender.send(price_report).unwrap();
                }
            }
        });
    }

    fn handle_event(swap: ethabi::Log) -> Option<PriceReport> {
        // Extract the `sqrtPriceX96` and convert it to the marginal price of the Uniswapv3 pool,
        // as per: https://docs.uniswap.org/sdk/v3/guides/fetching-prices#understanding-sqrtprice
        let sqrt_price_x96 = &swap.params[4].value;
        let sqrt_price_x96 = match sqrt_price_x96 {
            ethabi::Token::Uint(sqrt_price_x96) => sqrt_price_x96,
            _ => unreachable!(),
        };
        let price_numerator = U256::from(10).pow(U256::from(Self::BASE_DECIMALS))
            * U256::from(2).pow(U256::from(192));
        let price_denominator = U256::from(sqrt_price_x96).pow(U256::from(2));
        let price = price_numerator / price_denominator;
        let price = price.as_u32() as f32 / 10_f32.powf(Self::QUOTE_DECIMALS.into());
        Some(PriceReport {
            midpoint_price: price,
            reported_timestamp: None,
            local_timestamp: Default::default(),
        })
    }
}
