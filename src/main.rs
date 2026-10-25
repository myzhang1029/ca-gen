mod fetcher;
mod root_bundles;

use root_bundles::ROOT_BUNDLES;
use std::time::Duration;
use ureq::Agent;

use crate::fetcher::fetch_all;

fn main() {
    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let agent: Agent = config.into();
    let items = fetch_all(ROOT_BUNDLES, &agent).expect("Could not fetch certificates");
    println!("{items:?}");
}
