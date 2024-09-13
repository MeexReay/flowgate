use std::{fs, path::Path};

use flowgate::{Config, FlowgateServer};

fn main() {
    colog::init();

    if !Path::new("conf.yml").exists() {
        let _ = fs::write("conf.yml", include_bytes!("../conf.yml"));
    }

    let config = Config::parse("conf.yml").unwrap();
    let server = FlowgateServer::new(config);

    server.start();

    loop {}
}