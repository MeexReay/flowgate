use std::{fs, net::TcpStream, sync::Arc, time::Duration};

use serde_yml::{Number, Value};

use super::SslCert;

#[derive(Clone)]
pub struct SiteConfig {
    pub domain: String,
    pub host: String,
    pub ssl: Option<SslCert>,
    pub enable_keep_alive: bool,
    pub support_keep_alive: bool
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
    pub threadpool_size: usize,
    pub connection_timeout: Duration
}

impl Config {
    pub fn parse(filename: &str) -> Option<Config> {
        let file_content = fs::read_to_string(filename).ok()?;
        let doc = serde_yml::from_str::<Value>(file_content.as_str()).ok()?;

        let http_host = doc["http_host"].as_str()?.to_string();
        let https_host = doc["https_host"].as_str()?.to_string();

        let threadpool_size = doc.get("threadpool_size")
            .unwrap_or(&Value::Number(Number::from(10))).as_u64()? as usize;
        let connection_timeout = Duration::from_secs(doc.get("connection_timeout")
            .unwrap_or(&Value::Number(Number::from(10))).as_u64()?);

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
                enable_keep_alive: s.get("enable_keep_alive")
                    .map(|o| o.as_bool().unwrap())
                    .unwrap_or(true),
                support_keep_alive: s.get("support_keep_alive")
                    .map(|o| o.as_bool().unwrap())
                    .unwrap_or(true)
            };

            sites.push(site);
        }

        let sites = Arc::new(sites);

        Some(Config {
            sites,
            http_host,
            https_host,
            threadpool_size,
            connection_timeout
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