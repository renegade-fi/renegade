//! Groups configurations used throughout the relayer passed to the CLI

mod cli;
pub mod parsing;
mod token_remaps;
mod validation;

pub use cli::*;
pub use token_remaps::setup_token_remaps;
