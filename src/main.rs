mod config;

use std::thread;

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = config::parse_command_line_args();
    let version = match args.version {
        Some(s) => s,
        None => String::from("no version")
    };
    println!("Relayer running with\n\t version: {}\n\t port: {}", version, args.port);
}
