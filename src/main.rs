pub mod http_server;
extern crate yaml_rust;

use http_server::*;
use std::sync::Arc;
use std::{fs, thread};
use yaml_rust::YamlLoader;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

struct AppConfig {
    sites: Vec<Site>,
    http_host: String,
    https_host: String,
}

impl AppConfig {
    fn parse(filename: &str) -> Option<AppConfig> {
        let Ok(file_content) = fs::read_to_string(filename) else {
            return None;
        };
        let Ok(docs) = YamlLoader::load_from_str(file_content.as_str()) else {
            return None;
        };
        let doc = docs.get(0)?;

        let http_host = doc["http_host"].as_str()?.to_string();
        let https_host = doc["https_host"].as_str()?.to_string();

        let mut sites: Vec<Site> = Vec::new();

        let sites_yaml = doc["sites"].as_vec()?;

        for s in sites_yaml {
            let mut cert: Option<SslCert> = None;

            if !s["ssl_cert"].is_badvalue() && !s["ssl_cert"].is_null() {
                cert = Some(
                    SslCert::new(
                        s["ssl_cert"].as_str().unwrap(),
                        s["ssl_key"].as_str().unwrap(),
                    )
                    .unwrap(),
                );
            }

            let site = Site {
                domain: s["domain"].as_str().unwrap().to_string(),
                host: s["host"].as_str().unwrap().to_string(),
                ssl: cert,
            };

            sites.push(site);
        }

        Some(AppConfig {
            sites,
            http_host,
            https_host,
        })
    }
}

fn main() {
    log4rs::init_config(
        Config::builder()
            .appender(
                Appender::builder().build(
                    "logfile",
                    Box::new(
                        FileAppender::builder()
                            .encoder(Box::new(PatternEncoder::new(
                                "{d(%Y-%m-%d %H:%M:%S)} | {l} - {m}\n",
                            )))
                            .build("latest.log")
                            .unwrap(),
                    ),
                ),
            )
            .appender(
                Appender::builder().build(
                    "stdout",
                    Box::new(
                        ConsoleAppender::builder()
                            .encoder(Box::new(PatternEncoder::new(
                                "{d(%Y-%m-%d %H:%M:%S)} | {l} - {m}\n",
                            )))
                            .build(),
                    ),
                ),
            )
            .build(
                Root::builder()
                    .appender("logfile")
                    .appender("stdout")
                    .build(LevelFilter::Debug),
            )
            .unwrap(),
    )
    .unwrap();

    let config = AppConfig::parse("conf.yml").unwrap();
    let sites_arc = Arc::new(config.sites);

    let sites = sites_arc.clone();
    thread::spawn(move || {
        SiteServer::new(config.http_host.to_string(), sites).run_http();
    });

    let sites = sites_arc.clone();
    SiteServer::new(config.https_host.to_string(), sites).run_ssl();
}
