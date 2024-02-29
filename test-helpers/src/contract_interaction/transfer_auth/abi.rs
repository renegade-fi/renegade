//! Solidity type definitions for the relevant Permit2 structs

#![allow(missing_docs)]

use alloy_sol_types::sol;

// Types & methods from the Permit2 `ISignatureTransfer` interface, taken from https://github.com/Uniswap/permit2/blob/main/src/interfaces/ISignatureTransfer.sol
sol! {
    /// The token and amount details for a transfer signed in the permit transfer signature
    struct TokenPermissions {
        /// ERC20 token address
        address token;
        /// the maximum amount that can be spent
        uint256 amount;
    }

    /// The signed permit message for a single token transfer
    ///
    /// NOTE: This differs from the `PermitTransferFrom` struct in the `ISignatureTransfer` interface
    /// in that it includes the `spender` field. This field is signed and thus must be included in the
    /// EIP-712 hash, but is not included in the Solidity definition of the  `PermitTransferFrom` struct
    /// (as this field is injected by the Permit2 contract).
    struct PermitTransferFrom {
        /// The token permissions for the transfer
        TokenPermissions permitted;
        /// The address to which the transfer is made
        address spender;
        /// a unique value for every token owner's signature to prevent signature replays
        uint256 nonce;
        /// deadline on the permit signature
        uint256 deadline;
    }
}
