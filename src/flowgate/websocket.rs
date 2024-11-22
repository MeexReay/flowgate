use std::sync::{Arc, RwLock};

use serde_json::Value;
use websocket::{sync::Server, OwnedMessage};

use super::config::{Config, IpForwarding, SiteConfig};

fn on_message(config: Arc<RwLock<Config>>, data: Value) -> Option<()> {
    let data = data.as_object()?;
    if data.get("type")?.as_str()? == "set_site" {
        let mut conf = config.write().ok()?;
        let domain = data.get("domain")?.as_str()?;

        if let Some(site) = conf.sites.iter_mut().filter(|o| o.domain == domain).next() {
            site.host = data.get("host")?.as_str()?.to_string();
            site.enable_keep_alive = data.get("enable_keep_alive")?.as_bool()?;
            site.support_keep_alive = data.get("support_keep_alive")?.as_bool()?;
            site.ip_forwarding = IpForwarding::from_name(data.get("ip_forwarding")?.as_str()?)?;
        } else {
            conf.sites.push(SiteConfig {
                domain: domain.to_string(),
                host: data.get("host")?.as_str()?.to_string(),
                enable_keep_alive: data.get("enable_keep_alive")?.as_bool()?,
                support_keep_alive: data.get("support_keep_alive")?.as_bool()?,
                ip_forwarding: IpForwarding::from_name(data.get("ip_forwarding")?.as_str()?)?,
                ssl: None
            });
        }
    }

    Some(())
}

pub fn start_server(config: Arc<RwLock<Config>>) -> Option<()> {
    let mut server = Server::bind(config.read().ok()?.websocket_host.clone()?).ok()?;

    while let Ok(res) = server.accept() {
        let mut res = res.accept().ok()?;
        for msg in res.incoming_messages() {
            if let Ok(OwnedMessage::Text(msg)) = msg {
                if let Ok(data) = serde_json::from_str(&msg) {
                    if let None = on_message(config.clone(), data) {
                        break
                    }
                }
            } else {
                break
            }
        }
    }

    Some(())
}