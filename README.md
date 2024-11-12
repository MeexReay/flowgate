# Flowgate
HTTP requests redirection system

Features:
- Request redirection
- SSL/TLS support
- Keep-alive connections
- Sending IP in header (X-Real-IP)

TODO:
- Rustls support
- Remove panics
- Creating trees of flowgate

## Config

Default `conf.yml`:
```yml
http_host: localhost:80     # Http server host
https_host: localhost:443   # Https server host

threadpool_size: 10            # Threadpool size (count of threads that accept requests) (optional, default - 10)
connection_timeout: 10         # Read and write timeout of connections in seconds (optional, default - 10)
incoming_ip_forwarding: none   # Read IP forwarding on incoming connections (optional, default - none)

sites:
  - domain: localhost                                # Site domain (use wildcard matching)
    host: localhost:8080                             # Http server host
    ip_forwarding: simple                            # IP forwarding method type (optional, default - header)
    enable_keep_alive: true                          # Enable keep-alive connections (optional, default - true)
    support_keep_alive: true                         # Does server supports keep-alive connections (optional, default - true)
    # ssl_cert: "/path/to/public/certificate.txt"    # Ssl public certificate file (optional)
    # ssl_key: "/path/to/private/key.txt"            # Ssl private key file (optional)
```

### IP forwaring types

- None (`none`):\
  Do nothing
- Modern (`modern`):\
  Appends encoded to bytes ip to the beginning of the request
- Simple (`simple`):\
  Appends `ip:port\n` to the beginning of the request
- Header (`header[:HEADER_NAME]`):\
  Adds header `HEADER_NAME: ip:port` to the request

## How to run

You need [Rust](https://www.rust-lang.org/) installed with cargo!

Rust features:
- use-openssl
- use-rustls ([rustls](https://github.com/rustls/rustls) - openssl alternative)

```sh
cargo run # --------------------------------- # Run
cargo run --release # ----------------------- # Run release
cargo build && sudo ./target/release/flowgate # Run with root
cargo build # ------------------------------------------------ # Build
cargo build --release # -------------------------------------- # Build release
cargo build --release --no-default-features --features FEATURE # Build with feature
```