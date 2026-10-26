use crate::root_bundles::RootBundle;
use hex::ToHex;
use ring::digest::{self};
use rustls_pki_types::{
    CertificateDer,
    pem::{PemObject, SectionKind},
};
use std::collections::{HashMap, HashSet};
use ureq::Agent;

#[derive(Clone, Debug)]
pub struct CertificateStore<'name, 'cert> {
    name: &'name str,
    certificates: Vec<CertificateDer<'cert>>,
}

#[derive(Clone, Debug)]
pub struct CertificateInfo<'name, 'cert> {
    pub cert: CertificateDer<'cert>,
    pub trusted_by: HashSet<&'name str>,
    pub x509_name: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Network(#[from] ureq::Error),
    #[error(transparent)]
    Pem(#[from] rustls_pki_types::pem::Error),
    #[error(transparent)]
    X509(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
}

fn fetch_one(url: &str, agent: &Agent) -> Result<Vec<CertificateDer<'static>>, Error> {
    let body_rdr = agent.get(url).call()?.into_body().into_reader();
    let certs = PemObject::pem_reader_iter(body_rdr);
    certs
        .map(|r| {
            let pem: (SectionKind, Vec<u8>) = r?;
            let (section_kind, der_bytes) = pem;
            assert_eq!(section_kind, SectionKind::Certificate);
            let cert = CertificateDer::from(der_bytes.as_ref()).into_owned();
            Ok(cert)
        })
        .collect()
}

fn rotate<'name, 'cert>(
    tas: Vec<CertificateStore<'name, 'cert>>,
) -> Result<HashMap<String, CertificateInfo<'name, 'cert>>, Error> {
    let mut work: HashMap<String, CertificateInfo> = HashMap::new();
    for item in tas {
        let CertificateStore { name, certificates } = item;
        for cert in certificates {
            let (_, parsed_cert) = x509_parser::parse_x509_certificate(&cert)?;
            assert!(parsed_cert.is_ca());
            let issuer = parsed_cert.issuer();
            let subject = parsed_cert.subject();
            assert_eq!(issuer, subject, "root CA not self-signed");
            let fpr = digest::digest(&digest::SHA256, &cert);
            let fpr: String = fpr.encode_hex();
            let x509_name = subject.to_string();
            if let Some(info) = work.get_mut(&fpr) {
                assert_eq!(info.x509_name, x509_name);
                info.trusted_by.insert(name);
            } else {
                let mut trusted_by = HashSet::new();
                trusted_by.insert(name);
                let info = CertificateInfo {
                    cert,
                    trusted_by,
                    x509_name,
                };
                work.insert(fpr, info);
            }
        }
    }
    Ok(work)
}

pub fn fetch_all<'name, 'cert>(
    bundles: &'cert [RootBundle<'cert>],
    agent: &Agent,
) -> Result<HashMap<String, CertificateInfo<'name, 'cert>>, Error>
where
    'cert: 'name,
{
    let items: Vec<CertificateStore<'name, 'cert>> = bundles
        .iter()
        .map(|bundle| {
            let RootBundle { name, urls } = bundle;
            let certificates = urls
                .iter()
                .flat_map(|url| fetch_one(url, agent))
                .flatten()
                .collect();
            CertificateStore { name, certificates }
        })
        .collect();
    rotate(items)
}
