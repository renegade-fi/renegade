use std::fmt;

// Defines an error for Gossip operation
pub struct GossipError(String);

impl fmt::Display for GossipError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error during gossip operation: {}", self.0)
    }
}