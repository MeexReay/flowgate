use std::{fs, net::TcpStream, sync::Arc};

use serde_yml::Value;

use super::SslCert;

#[derive(Clone)]
pub struct SiteConfig {
    pub domain: String,
    pub host: String,
    pub ssl: Option<SslCert>,
}

impl SiteConfig {
    pub fn connect(self) -> Option<TcpStream> {
        TcpStream::connect(self.host).ok()
    }
}

#[derive(Clone)]
pub struct Config {
    pub sites: Arc<Vec<SiteConfig>>,
    pub http_host: String,
    pub https_host: String,
}

impl Config {
    pub fn parse(filename: &str) -> Option<Config> {
        let Ok(file_content) = fs::read_to_string(filename) else {
            return None;
        };
        let Ok(docs) = serde_yml::from_str::<Value>(file_content.as_str()) else {
            return None;
        };
        let doc = docs.get(0)?;

        let http_host = doc["http_host"].as_str()?.to_string();
        let https_host = doc["https_host"].as_str()?.to_string();

        let mut sites: Vec<SiteConfig> = Vec::new();

        let sites_yaml = doc["sites"].as_sequence()?;

        for s in sites_yaml {
            let mut cert: Option<SslCert> = None;
            let s = s.as_mapping()?;

            if s.contains_key("ssl_cert") && !s.get("ssl_cert")?.is_null() {
                cert = Some(
                    SslCert::new(
                        s.get("ssl_cert")?.as_str()?,
                        s.get("ssl_key")?.as_str()?,
                    )?,
                );
            }

            let site = SiteConfig {
                domain: s.get("domain")?.as_str()?.to_string(),
                host: s.get("host")?.as_str()?.to_string(),
                ssl: cert,
            };

            sites.push(site);
        }

        Some(Config {
            sites: Arc::new(sites),
            http_host,
            https_host,
        })
    }

    pub fn get_site(&self, domain: &str) -> Option<&SiteConfig> {
        for i in self.sites.as_ref() {
            if i.domain == domain {
                return Some(i);
            }
        }
        return None;
    }
}