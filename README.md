# Flowgate
HTTP requests redirection system

Features:
- Request redirection
- SSL/TLS support
- Keep-alive connections
- Rustls support (not yet)

## Config

Default `conf.yml`:
```yml
http_host: localhost:80           # Http server host
https_host: localhost:443         # Https server host

threadpool_size: 10            # Threadpool size (count of threads that accept requests)
connection_timeout: 10         # Read and write timeout of connections in seconds

sites:
  - domain: localhost                                # Site domain
    host: localhost:8080                             # Http server host
    support_keep_alive: false                        # Does server supports keep-alive connections
    # ssl_cert: "/path/to/public/certificate.txt"    # Ssl public certificate file (optional)
    # ssl_key: "/path/to/private/key.txt"            # Ssl private key file (optional)
```

## How to run

You need [Rust](https://www.rust-lang.org/) installed with cargo!

Rust features:
- use-openssl
- use-rustls ([rustls](https://github.com/rustls/rustls) - openssl alternative)

```sh
cargo run # Run
cargo run --release # Run release
cargo build && sudo ./target/release/flowgate # Run with root
cargo build # Build
cargo build --release # Build release
cargo build --release --no-default-features --features FEATURE # Build with feature
```