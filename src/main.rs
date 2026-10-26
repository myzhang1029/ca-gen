mod fetcher;
mod io;
mod root_bundles;

use crate::root_bundles::{DEFAULT_BUNDLES, RootBundle};
use clap::{Parser, Subcommand};
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug, Parser)]
#[command(name = "ca-gen")]
struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[arg(short = 'p', long, default_value = ".")]
    pub path: PathBuf,
}

#[derive(Debug, Subcommand)]
enum Command {
    Download {
        #[arg(short = 's', long, help = "additional root trust bundle URL (name:URL)")]
        sources: Vec<RootBundle>,
        #[arg(short = 'n', long, help = "automatically mark certificates trusted by more than so many sources as trusted")]
        num_required: usize,
    },
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
    let cli = Box::leak(Box::new(Cli::parse()));
    match cli.command {
        Command::Download {
            sources: ref user_sources,
            num_required,
        } => {
            let mut sources: HashMap<&'static str, &'static [http::Uri]> = HashMap::new();
            for source in &*DEFAULT_BUNDLES {
                sources.insert(&source.name, &source.urls);
            }
            for source in user_sources {
                sources.insert(&source.name, &source.urls);
            }
            io::download(&cli.path, &sources, num_required)
        }
        Command::Generate => io::generate_bundle(&cli.path),
    }
}
