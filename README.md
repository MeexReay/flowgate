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

sites:
  # - domain: example.com                            # Domain with SSL
  #   host: localhost:8080                           # Http server host
  #   ssl_cert: "/path/to/public/certificate.txt"    # Ssl public certificate file
  #   ssl_key: "/path/to/private/key.txt"            # Ssl private key file
  #   support_keep_alive: true                       # Does server supports keep-alive connections

  # - domain: sub.example.com                        # Domain with no SSL
  #   host: localhost:8081                           # Http server host
  #   support_keep_alive: true                       # Does server supports keep-alive connections

  - domain: localhost
    host: localhost:8080
    support_keep_alive: false
```

Rust features:
- use-openssl
- use-rustls ([rustls](https://github.com/rustls/rustls) - openssl alternative)
