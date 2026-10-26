use crate::{Error, fetcher};
use http::Uri;
use pem::Pem;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::{fmt::Write, path::Path, time::Duration};
use ureq::Agent;

const INDEX_FILENAME: &str = "ca-certificates.conf";

#[derive(Clone, Debug)]
pub struct Entry {
    pub fpr: String,
    pub name: String,
    pub enabled: bool,
}

pub fn download(path: &Path, bundles: &HashMap<&str, &[Uri]>, num_required: usize) -> Result<(), Error> {
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build()
        .into();
    let cert_dir = path.join("certs");
    fs::create_dir_all(&cert_dir)?;
    let mut index = String::new();
    let mut entries = fetcher::fetch_all(bundles, &agent)?
        .into_iter()
        .collect::<Vec<_>>();
    // Sort by fingerprint
    entries.sort_by(|(l, _), (r, _)| l.cmp(r));
    for (fpr, info) in entries {
        let marker = if info.trusted_by.len() >= num_required {
            ""
        } else {
            "!"
        };
        writeln!(index, "{marker}{fpr} {} {:?}", info.x509_name, info.trusted_by).expect("cannot write into a `String`");
        let pem = pem::encode(&Pem::new("CERTIFICATE", info.cert.to_vec()));
        fs::write(cert_dir.join(format!("{fpr}.pem")), pem)?;
    }
    fs::write(path.join(INDEX_FILENAME), index)?;
    println!("Downloaded certificates to {}", path.display());
    Ok(())
}

pub fn read_index(path: &Path) -> Result<Vec<Entry>, Error> {
    let file = BufReader::new(File::open(path.join(INDEX_FILENAME))?);
    file.lines()
        .filter_map(|line| {
            match line {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        return None;
                    }
                    let disabled = line.starts_with('!');
                    let (fpr, name) = line.split_once(' ').unwrap_or((line, ""));
                    // This is impossible by construction (the leading space would be stripped)
                    assert_ne!(fpr, "");
                    Some(Ok(Entry {
                        fpr: fpr.to_string(),
                        name: name.to_string(),
                        enabled: !disabled,
                    }))
                }
                Err(e) => Some(Err(e.into())),
            }
        })
        .collect()
}

pub fn generate_bundle(path: &Path) -> Result<(), super::Error> {
    let entries = read_index(path)?;
    for entry in entries.into_iter().filter(|entry| entry.enabled) {
        let cert_path = path.join(format!("certs/{}.pem", entry.fpr));
        let cert = fs::read_to_string(&cert_path)?;
        print!("# {} {}\n{cert}", entry.fpr, entry.name);
    }
    Ok(())
}
