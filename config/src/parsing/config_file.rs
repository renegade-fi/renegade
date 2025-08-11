//! Parsing logic for a separate relayer config file

use std::fs;

use clap::Parser;
use toml::{Value, map::Map};

use crate::{Cli, RelayerConfig, parsing::parse_config_from_args, validation::validate_config};

/// The CLI argument name for the config file
const CONFIG_FILE_ARG: &str = "--config-file";

/// Parse args from a config file
pub(crate) fn config_file_args(cli_args: &[String]) -> Result<Vec<String>, String> {
    // Find a match for the config file argument
    let mut found = false;
    let mut index = 0;

    for arg in cli_args.iter() {
        index += 1;
        // If we find "--config-file", the next argument is the file to read from
        if arg == CONFIG_FILE_ARG {
            found = true;
            break;
        }
    }

    // No config file found
    if !found {
        return Ok(vec![]);
    }
    read_config_file(&cli_args[index])
}

/// Parse a config entirely from a file
pub fn parse_config_from_file(path: &str) -> Result<RelayerConfig, String> {
    let mut file_args = read_config_file(path)?;
    file_args.insert(0, "dummy-program-name".to_string());
    let cli = Cli::parse_from(file_args);
    let config = parse_config_from_args(cli)?;
    validate_config(&config)?;
    Ok(config)
}

/// Parse a config file
fn read_config_file(path: &str) -> Result<Vec<String>, String> {
    // Read in the config file
    let file_contents = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let config_kv_pairs: Map<_, _> =
        toml::from_str(&file_contents).map_err(|err| err.to_string())?;

    let mut config_file_args: Vec<String> = Vec::with_capacity(config_kv_pairs.len());
    for (toml_key, value) in config_kv_pairs.iter() {
        // Format the TOML key into --key
        let cli_arg = format!("--{}", toml_key);

        // Parse the values for this TOML entry into a CLI-style vector of strings
        let values: Vec<String> = match value {
            // Just the flag, i.e. --flag, if the value is true.
            // Otherwise, omit the flag
            Value::Boolean(val) => {
                if *val {
                    vec![cli_arg]
                } else {
                    vec![]
                }
            },
            // Parse all values into multiple repetitions, i.e. --key val1 --key val2 ...
            Value::Array(arr) => {
                let mut res: Vec<String> = Vec::new();
                for val in arr.iter() {
                    res.push(cli_arg.clone());
                    res.push(toml_value_to_string(val)?);
                }

                res
            },
            // All other type may simply be parsed as --key val
            _ => {
                vec![
                    cli_arg.clone(),
                    toml_value_to_string(value).map_err(|_| {
                        format!("error parsing config value: {:?} = {:?}", cli_arg, value)
                    })?,
                ]
            },
        };

        config_file_args.extend(values);
    }

    Ok(config_file_args)
}

/// Helper method to convert a toml value to a string
fn toml_value_to_string(val: &Value) -> Result<String, String> {
    Ok(match val {
        Value::String(val) => val.clone(),
        Value::Integer(val) => format!("{:?}", val),
        Value::Float(val) => format!("{:?}", val),
        Value::Boolean(val) => format!("{:?}", val),
        _ => {
            return Err("unsupported value".to_string());
        },
    })
}
