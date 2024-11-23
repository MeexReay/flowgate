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

## IP forwarding types

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