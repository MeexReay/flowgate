mod flowgate;

use flowgate::{Config, FlowgateServer};

fn main() {
    pretty_env_logger::init();

    let config = Config::parse("conf.yml").unwrap();
    let server = FlowgateServer::new(config);

    server.start();
}
