//! Builder for the state crate's protos

use std::io::Result;

use prost_build::Config;

/// Build the protos for the state crate
fn main() -> Result<()> {
    let mut builder_config = Config::default();
    // Derive a builder pattern for each generated message
    // The builder options enabled are:
    // - Use the owned pattern, i.e. each setter consumes the builder and returns a new one
    // - Allow uninitialized fields by deferring to the struct default implementation
    // - Strip options; i.e. setters do no take `Option<T>` but `T` for optional fields, which is the
    //   case for most prost-generated fields
    let builder_pattern_targets = ".";
    builder_config.message_attribute(
        builder_pattern_targets,
        "#[derive(derive_builder::Builder, serde::Serialize, serde::Deserialize)]",
    );
    builder_config.message_attribute(builder_pattern_targets, "#[builder(pattern = \"owned\")]");
    builder_config.message_attribute(builder_pattern_targets, "#[builder(default)]");
    builder_config.message_attribute(builder_pattern_targets, "#[builder(setter(strip_option))]");

    builder_config.compile_protos(&["proto/state_transitions.proto"], &["proto/"])?;
    Ok(())
}
