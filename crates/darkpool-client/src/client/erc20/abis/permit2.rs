//! ABI definitions for Permit2
//!
//! Note that these definitions only contain the `IAllowanceTransfer` interface,
//! which is a subset of the full Permit2 contract.
use alloy::sol;

sol! {
    #[sol(rpc)]
    contract IPermit2 {
        // Errors
        error AllowanceExpired(uint256 deadline);
        error InsufficientAllowance(uint256 amount);

        // Events
        event NonceInvalidation(address indexed owner, address indexed token, address indexed spender, uint48 newNonce, uint48 oldNonce);
        event Approval(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration);
        event Permit(address indexed owner, address indexed token, address indexed spender, uint160 amount, uint48 expiration, uint48 nonce);

        // Functions
        function allowance(address user, address token, address spender) external view returns (uint160 amount, uint48 expiration, uint48 nonce);
        function approve(address token, address spender, uint160 amount, uint48 expiration) external;
        function permit(address owner, PermitSingle memory permitSingle, bytes calldata signature) external;
        function permit(address owner, PermitBatch memory permitBatch, bytes calldata signature) external;
        function transferFrom(address from, address to, uint160 amount, address token) external;
        function transferFrom(AllowanceTransferDetails[] calldata transferDetails) external;
        function invalidateNonces(address token, address spender, uint48 newNonce) external;

        // Types
        struct PermitDetails {
            // ERC20 token address
            address token;
            // the maximum amount allowed to spend
            uint160 amount;
            // timestamp at which a spender's token allowances become invalid
            uint48 expiration;
            // an incrementing value indexed per owner,token,and spender for each signature
            uint48 nonce;
        }

        struct PermitSingle {
            // the permit data for a single token alownce
            PermitDetails details;
            // address permissioned on the allowed tokens
            address spender;
            // deadline on the permit signature
            uint256 sigDeadline;
        }

        /// @notice The permit message signed for multiple token allowances
        struct PermitBatch {
            // the permit data for multiple token allowances
            PermitDetails[] details;
            // address permissioned on the allowed tokens
            address spender;
            // deadline on the permit signature
            uint256 sigDeadline;
        }

        /// @notice The saved permissions
        /// @dev This info is saved per owner, per token, per spender and all signed over in the permit message
        /// @dev Setting amount to type(uint160).max sets an unlimited approval
        struct PackedAllowance {
            // amount allowed
            uint160 amount;
            // permission expiry
            uint48 expiration;
            // an incrementing value indexed per owner,token,and spender for each signature
            uint48 nonce;
        }

        /// @notice A token spender pair.
        struct TokenSpenderPair {
            // the token the spender is approved
            address token;
            // the spender address
            address spender;
        }

        /// @notice Details for a token transfer.
        struct AllowanceTransferDetails {
            // the owner of the token
            address from;
            // the recipient of the token
            address to;
            // the amount of the token
            uint160 amount;
            // the token to be transferred
            address token;
        }

    }
}
