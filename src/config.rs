use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
// Defines the relayer system config
pub struct Cli {
    #[clap(short, long, value_parser)]
    // The software version of the relayer
    pub version: Option<String>,

    #[clap(short, long, value_parser, default_value="12345")]
    // The port to listen on
    pub port: u32,
}

// Parses command line args into the node config
pub fn parse_command_line_args() -> Box<Cli> {
    Box::new(Cli::parse())
}