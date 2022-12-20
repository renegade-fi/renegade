#[derive(Clone, Copy, Debug)]
pub enum Token {
    None,
    Usdc,
    Eth,
}

impl Default for Token {
    fn default() -> Self {
        Self::None
    }
}
