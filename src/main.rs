mod flowgate;

use flowgate::{Config, FlowgateServer};

fn main() {
    colog::init();

    let config = Config::parse("conf.yml").unwrap();
    let server = FlowgateServer::new(config);

    server.start();

    loop {}
}
