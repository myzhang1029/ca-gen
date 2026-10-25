mod root_bundles;

use aws_lc_rs::digest::{self};
use hex::ToHex;
use root_bundles::{ROOT_BUNDLES, RootBundle};
use rustls_pki_types::{
    CertificateDer,
    pem::{PemObject, SectionKind},
};
use std::{collections::HashMap, time::Duration};
use ureq::Agent;

#[derive(Clone, Debug)]
struct CertificateStore<'name, 'cert> {
    name: &'name str,
    certificates: Vec<CertificateDer<'cert>>,
}

#[derive(Clone, Debug)]
struct CertificateInfo<'name, 'cert> {
    cert: CertificateDer<'cert>,
    trusted_by: Vec<&'name str>,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error(transparent)]
    Network(#[from] ureq::Error),
    #[error(transparent)]
    Pem(#[from] rustls_pki_types::pem::Error),
    #[error(transparent)]
    X509(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error(transparent)]
    Webpki(#[from] webpki::Error),
}

fn fetch_one(url: &str, agent: &Agent) -> Result<Vec<CertificateDer<'static>>, Error> {
    let body_rdr = agent.get(url).call()?.into_body().into_reader();
    let certs = PemObject::pem_reader_iter(body_rdr);
    certs
        .map(|r| {
            let pem: (SectionKind, Vec<u8>) = r?;
            let (section_kind, der_bytes) = pem;
            assert_eq!(section_kind, SectionKind::Certificate);
            let (_, parsed_cert) = x509_parser::parse_x509_certificate(&der_bytes)?;
            assert!(parsed_cert.is_ca());
            let issuer = parsed_cert.issuer();
            let subject = parsed_cert.subject();
            assert_eq!(issuer, subject, "root CA not self-signed");

            let cert = CertificateDer::from(der_bytes.as_ref()).into_owned();
            Ok(cert)
        })
        .collect()
}

fn rotate<'name, 'cert>(
    mut tas: Vec<CertificateStore<'name, 'cert>>,
) -> Result<HashMap<String, CertificateInfo<'name, 'cert>>, webpki::Error> {
    let mut work: HashMap<String, CertificateInfo> = HashMap::new();
    for item in tas.drain(..) {
        let CertificateStore { name, certificates } = item;
        for cert in certificates {
            let fpr = digest::digest(&digest::SHA256, &cert);
            let fpr: String = fpr.encode_hex();
            if let Some(info) = work.get_mut(&fpr) {
                info.trusted_by.push(name);
            } else {
                let trusted_by = vec![name];
                work.insert(fpr, CertificateInfo { cert, trusted_by });
            }
        }
    }
    Ok(work)
}

fn main() {
    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let agent: Agent = config.into();
    let items: Vec<CertificateStore<'static, 'static>> = ROOT_BUNDLES
        .iter()
        .map(|bundle| {
            let RootBundle { name, urls } = bundle;
            let certificates = urls
                .iter()
                .flat_map(|url| fetch_one(url, &agent).expect("failed"))
                .collect();
            CertificateStore { name, certificates }
        })
        .collect();
    let items = rotate(items);
    println!("{items:?}");
}
