#[cfg(feature = "use-openssl")]
use openssl::ssl::SslContext;

#[cfg(feature = "use-openssl")]
#[derive(Clone)]
pub struct SslCert {
    context: SslContext,
}

#[cfg(feature = "use-openssl")]
fn generate_ctx(cert_file: &str, key_file: &str) -> Option<SslContext> {
    use openssl::ssl::{SslFiletype, SslMethod};

    let mut ctx = SslContext::builder(SslMethod::tls()).ok()?;
    ctx.set_private_key_file(&key_file, SslFiletype::PEM).ok()?;
    ctx.set_certificate_file(&cert_file, SslFiletype::PEM).ok()?;
    ctx.check_private_key().ok()?;
    Some(ctx.build())
}

#[cfg(feature = "use-openssl")]
impl SslCert {
    pub fn new(cert_file: &str, key_file: &str) -> Option<SslCert> {
        Some(SslCert {
            context: generate_ctx(cert_file, key_file)?
        })
    }

    pub fn get_context(&self) -> SslContext {
        self.context.clone()
    }
}

#[cfg(feature = "use-rustls")]
use rustls::{sign::CertifiedKey, server::Acceptor, ServerConfig, ServerConnection};
#[cfg(feature = "use-rustls")]
use std::{net::TcpStream, sync::Arc};

#[cfg(feature = "use-rustls")]
#[derive(Clone)]
pub struct SslCert {
    cert_key: CertifiedKey,
}

#[cfg(feature = "use-rustls")]
fn generate_cert_key(cert_file: &str, key_file: &str) -> Option<CertifiedKey> {
    use rustls::crypto::CryptoProvider;
    use std::fs::File;
    use std::io::BufReader;

    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key_file).ok()?)).ok()??;
    let key = CryptoProvider::get_default().unwrap().key_provider.load_private_key(key).ok()?;

    let cert = 
        rustls_pemfile::public_keys(&mut BufReader::new(File::open(cert_file).ok()?))
        .map(|o| o.unwrap().to_vec().into())
        .collect::<Vec<_>>();
    Some(CertifiedKey::new(cert, key))
}

#[cfg(feature = "use-rustls")]
impl SslCert {
    pub fn new(cert_file: &str, key_file: &str) -> Option<SslCert> {
        Some(SslCert {
            cert_key: generate_cert_key(cert_file, key_file)?,
        })
    }

    pub fn get_certified_key(&self) -> CertifiedKey {
        self.cert_key.clone()
    }
}

#[cfg(feature = "use-rustls")]
pub struct AdoptedConnection {
    server_connection: ServerConnection,
    stream: TcpStream
}

#[cfg(feature = "use-rustls")]
impl AdoptedConnection {
    pub fn new(
        server_connection: ServerConnection,
        stream: TcpStream
    ) -> AdoptedConnection {
        AdoptedConnection {
            server_connection,
            stream
        }
    }

    pub fn from_config(
        server_config: Arc<ServerConfig>,
        mut stream: TcpStream
    ) -> Option<AdoptedConnection> {
        let mut acceptor = Acceptor::default();
        let accepted = loop {
            acceptor.read_tls(&mut stream).ok()?;
            if let Some(accepted) = acceptor.accept().ok()? {
                break accepted;
            }
        };

        Some(AdoptedConnection {
            server_connection: accepted.into_connection(server_config).ok()?,
            stream
        })
    }
}

// TODO: implement Read and Write to AdoptedConnection