#[derive(Clone, Copy, Debug)]
pub enum Token {
    NONE,
    USDC,
    ETH,
}

impl Default for Token {
    fn default() -> Self {
        Self::NONE
    }
}
