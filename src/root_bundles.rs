use http::Uri;
use std::{str::FromStr, sync::LazyLock};

#[derive(Clone, Debug)]
pub struct RootBundle {
    pub name: String,
    pub urls: Vec<Uri>,
}

impl FromStr for RootBundle {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, url) = s.split_once(':').ok_or("bad source string")?;
        Ok(Self {
            name: String::from(name),
            urls: vec![Uri::try_from(url).map_err(|e| e.to_string())?],
        })
    }
}

pub static DEFAULT_BUNDLES: LazyLock<Vec<RootBundle>> = LazyLock::new(|| {
    vec![
        RootBundle {
            name: "chrome".to_string(),
            urls: vec![
                "https://github.com/chromium/chromium/raw/refs/heads/main/net/data/ssl/chrome_root_store/root_store.certs".parse().unwrap(),
            ],
        },
        RootBundle {
            name: "mozilla".to_string(),
            urls: vec![
                "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites".parse().unwrap(),
            ],
        },
        RootBundle {
            name: "python-certifi".to_string(),
            urls: vec![
                "https://github.com/certifi/python-certifi/raw/refs/heads/master/certifi/cacert.pem".parse().unwrap(),
            ],
        },
    ]
});
