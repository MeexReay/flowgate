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
http_host: localhost:80
https_host: localhost:443

sites:
  # - domain: example.com                            # Domain with SSL
  #   host: localhost:8080
  #   ssl_cert: "/path/to/public/certificate.txt"
  #   ssl_key: "/path/to/private/key.txt"

  # - domain: sub.example.com                        # Domain with no SSL
  #   host: localhost:8081

  - domain: localhost
    host: localhost:8080
```

Rust features:
- use-openssl
- use-rustls ([rustls](https://github.com/rustls/rustls) - openssl alternative)
