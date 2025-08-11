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
        let cli_values = parse_toml_value(cli_arg, value)?;
        config_file_args.extend(cli_values);
    }

    Ok(config_file_args)
}

// ----------------
// | TOML Parsing |
// ----------------

/// Parse a toml value into a list of strings to append to the CLI args
fn parse_toml_value(cli_arg: String, val: &Value) -> Result<Vec<String>, String> {
    // Parse the values for this TOML entry into a CLI-style vector of strings
    let values: Vec<String> = match val {
        Value::Boolean(b) => toml_boolean_to_args(cli_arg, *b),
        Value::Array(arr) => toml_array_to_args(&cli_arg, arr)?,
        Value::Table(table) => toml_table_to_args(cli_arg, table)?,
        x => toml_value_to_args(cli_arg, x)?,
    };

    Ok(values)
}

/// Parse a toml boolean into a string that is CLI compatible
///
/// This will be "--key" if the boolean is true, otherwise it will be empty
fn toml_boolean_to_args(cli_arg: String, b: bool) -> Vec<String> {
    if b { vec![cli_arg] } else { vec![] }
}

/// Parse a toml array into a string that is CLI compatible
///
/// This will be "--arg val1 --arg val2 --arg val3"
///
/// We assume that the array has no nested arrays
fn toml_array_to_args(cli_arg: &str, arr: &[Value]) -> Result<Vec<String>, String> {
    let mut res: Vec<String> = Vec::new();
    for val in arr.iter() {
        res.push(cli_arg.to_string());
        res.push(toml_value_to_string(val)?);
    }

    Ok(res)
}

/// Parse a toml table into a string that is CLI compatible
///
/// This will be "--arg key1=value1,key2=value2,..."
///
/// We assume that the table has no nested tables
fn toml_table_to_args(cli_arg: String, table: &Map<String, Value>) -> Result<Vec<String>, String> {
    let mut res = String::new();
    for (key, value) in table.iter() {
        let value_str = toml_value_to_string(value)?;
        res.push_str(&format!("{key}={value_str},"));
    }

    Ok(vec![cli_arg, res])
}

/// Parse a toml value into a string that is CLI compatible
fn toml_value_to_args(cli_arg: String, val: &Value) -> Result<Vec<String>, String> {
    let value_str = toml_value_to_string(val)?;
    Ok(vec![cli_arg, value_str])
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
