use std::io::Result;

/// Build the protos for the state crate
fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/state_transitions.proto"], &["proto/"])?;
    Ok(())
}
