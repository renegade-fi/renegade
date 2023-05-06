//! Groups together long-running async tasks for best discoverability
//!
//! Examples of such tasks are creating a new wallet; which requires the
//! node to prove `VALID NEW WALLET`, submit the wallet on-chain, wait for
//! transaction success, and then prove `VALID COMMITMENTS`

pub mod create_new_wallet;
pub mod driver;
mod helpers;
pub mod initialize_state;
pub mod lookup_wallet;
pub mod settle_match;
pub mod update_wallet;
