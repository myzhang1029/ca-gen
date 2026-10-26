mod fetcher;
mod io;
mod root_bundles;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ca-gen")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(short = 'p', long, default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Download,
    Generate,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Fetch(#[from] fetcher::Error),
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    match cli.command {
        Command::Download => io::download(&cli.path),
        Command::Generate => io::generate_bundle(&cli.path),
    }
}
