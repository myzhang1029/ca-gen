#[derive(Copy, Clone, Debug)]
// Lifetimes are likely 'static
pub struct RootBundle<'a> {
    pub name: &'a str,
    pub urls: &'a [&'a str],
}

pub const ROOT_BUNDLES: &[RootBundle] = &[
    RootBundle {
        name: "chrome",
        urls: &[
            "https://github.com/chromium/chromium/raw/refs/heads/main/net/data/ssl/chrome_root_store/root_store.certs",
        ],
    },
    RootBundle {
        name: "mozilla",
        urls: &[
            "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites",
        ],
    },
    RootBundle {
        name: "python-certifi",
        urls: &[
            "https://github.com/certifi/python-certifi/raw/refs/heads/master/certifi/cacert.pem",
        ],
    },
];
