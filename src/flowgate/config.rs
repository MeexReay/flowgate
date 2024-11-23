use std::{fs, net::TcpStream, time::Duration};

use serde_yml::{Number, Value};
use wildcard_ex::is_match_simple;

use super::ssl_cert::SslCert;

#[derive(Clone)]
pub struct SiteConfig {
    pub domain: String,
    pub host: String,
    pub ssl: Option<SslCert>,
    pub enable_keep_alive: bool,
    pub support_keep_alive: bool,
    pub ip_forwarding: IpForwarding,
    pub replace_host: Option<String>
}

impl SiteConfig {
    pub fn connect(&self) -> Option<TcpStream> {
        TcpStream::connect(self.host.clone()).ok()
    }
}

#[derive(Clone)]
pub enum IpForwarding {
    Simple,
    Header(String),
    Modern,
    None
}

impl IpForwarding {
    pub fn from_name(name: &str) -> Option<IpForwarding> {
        match name {
            "none" => Some(IpForwarding::None),
            "simple" => Some(IpForwarding::Simple),
            "modern" => Some(IpForwarding::Modern),
            "header" => Some(IpForwarding::Header(String::from("X-Real-IP"))),
            name => if name.starts_with("header:") {
                Some(IpForwarding::Header(name[7..].to_string()))
            } else {
                None
            }
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub sites: Vec<SiteConfig>,
    pub http_host: String,
    pub https_host: String,
    pub threadpool_size: usize,
    pub connection_timeout: Duration,
    pub incoming_ip_forwarding: IpForwarding,
    pub websocket_host: Option<String>
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
        let incoming_ip_forwarding = doc.get("incoming_ip_forwarding")
            .map(|o| o.as_str()).flatten()
            .map(|o| IpForwarding::from_name(o)).flatten()
            .unwrap_or(IpForwarding::None);
        let websocket_host = doc.get("websocket_host").map(|o| o.as_str()).flatten().map(|o| o.to_string());

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
                    .unwrap_or(true),
                ip_forwarding: s.get("ip_forwarding")
                    .map(|o| o.as_str()).flatten()
                    .map(|o| IpForwarding::from_name(o)).flatten()
                    .unwrap_or(IpForwarding::Header("X-Real-IP".to_string())),
                replace_host: s.get("replace_host")
                    .map(|o| o.as_str()).flatten().map(|o| o.to_string()),
            };

            sites.push(site);
        }

        Some(Config {
            sites,
            http_host,
            https_host,
            threadpool_size,
            connection_timeout,
            incoming_ip_forwarding,
            websocket_host
        }.clone())
    }

    pub fn get_site(&self, domain: &str) -> Option<&SiteConfig> {
        for i in &self.sites {
            if is_match_simple(&i.domain, domain) {
                return Some(i);
            }
        }
        return None;
    }
}