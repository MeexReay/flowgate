use std::{fs, path::Path, sync::{Arc, RwLock}};

use flowgate::{config::Config, server::FlowgateServer, websocket};

fn main() {
    colog::init();

    if !Path::new("conf.yml").exists() {
        let _ = fs::write("conf.yml", include_bytes!("../conf.yml"));
    }

    let config = Arc::new(RwLock::new(Config::parse("conf.yml").unwrap()));
    let server = FlowgateServer::new(config.clone());

    server.start();

    if config.read().unwrap().websocket_host.is_some() {
        websocket::start_server(config);
    } else {
        loop {}
    }
}