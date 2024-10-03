use std::{io::{Read, Write}, net::{Shutdown, SocketAddr, TcpListener}, sync::Arc, thread, time::Duration};

use log::info;
use threadpool::ThreadPool;

use super::{Closeable, Config};

pub struct FlowgateServer {
    config: Arc<Config>,
}

impl FlowgateServer {
    pub fn new(config: Config) -> Self {
        FlowgateServer { config: Arc::new(config) }
    }

    pub fn start(&self) {
        thread::spawn({
            let config = Arc::clone(&self.config);
            
            move || {
                Self::run_http(config)
            }
        });

        thread::spawn({
            let config = Arc::clone(&self.config);
            
            move || {
                Self::run_https(config)
            }
        });
    }

    pub fn run_http(
        config: Arc<Config>
    ) -> Option<()> {
        let listener = TcpListener::bind(&config.http_host).ok()?;

        let pool = ThreadPool::new(10);

        info!("HTTP server runned on {}", &config.http_host);

        for stream in listener.incoming() {
            pool.execute({
                let config = config.clone();

                move || {
                    let Ok(mut stream) = stream else { return };

                    let Ok(_) = stream.set_write_timeout(Some(Duration::from_secs(10))) else { return };
                    let Ok(_) = stream.set_read_timeout(Some(Duration::from_secs(10))) else { return };

                    let Ok(addr) = stream.peer_addr() else { return };

                    Self::accept_stream(
                        config,
                        &mut stream,
                        addr,
                        false
                    );
                }
            });
        }

        Some(())
    }

    #[cfg(feature = "use-openssl")]
    pub fn run_https(
        config: Arc<Config>
    ) -> Option<()> {
        use openssl::ssl::{NameType, SniError, SslAcceptor, SslAlert, SslMethod, SslRef};

        let listener = TcpListener::bind(&config.https_host).ok()?;

        let mut cert = SslAcceptor::mozilla_intermediate(SslMethod::tls()).ok()?;

        cert.set_servername_callback(Box::new({
                let config = config.clone();

                move |ssl: &mut SslRef, _: &mut SslAlert| -> Result<(), SniError> {
                    let servname = ssl.servername(NameType::HOST_NAME).ok_or(SniError::NOACK)?;
                    let cert = config.get_site(servname).ok_or(SniError::NOACK)?;
                    ssl.set_ssl_context(&cert.ssl.as_ref().ok_or(SniError::NOACK)?.get_context()).ok().ok_or(SniError::NOACK)
                }
            }
        ));

        let cert = cert.build();

        let pool = ThreadPool::new(config.threadpool_size);

        info!("HTTPS server runned on {}", &config.https_host);

        for stream in listener.incoming() {
            pool.execute({
                let config = config.clone();
                let cert = cert.clone();

                move || {
                    let Ok(stream) = stream else { return };
                    
                    let Ok(_) = stream.set_write_timeout(Some(config.connection_timeout)) else { return };
                    let Ok(_) = stream.set_read_timeout(Some(config.connection_timeout)) else { return };

                    let Ok(addr) = stream.peer_addr() else { return };

                    let Ok(mut stream) = cert.accept(stream) else { return };

                    Self::accept_stream(
                        config,
                        &mut stream,
                        addr,
                        true
                    );
                }
            });
        }

        Some(())
    }

    #[cfg(feature = "use-rustls")]
    pub fn run_https(
        config: Arc<Config>
    ) -> Option<()> {
        use std::sync::Arc;
        use rustls::{server::ResolvesServerCertUsingSni, ServerConfig};
        use super::ssl_cert::AdoptedConnection;

        let listener = TcpListener::bind(&config.https_host).ok()?;

        let mut cert_resolver = ResolvesServerCertUsingSni::new();

        for site in config.sites.iter() {
            if let Some(cert) = site.ssl {
                cert_resolver.add(&site.domain, cert.get_certified_key());
            }
        }

        let mut tls_config = Arc::new(
            ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(cert_resolver))
        );

        let pool = ThreadPool::new(10);

        info!("HTTPS server runned on {}", &config.https_host);

        for stream in listener.incoming() {
            pool.execute({
                let config = config.clone();
                let tls_config = tls_config.clone();

                move || {
                    let Ok(mut stream) = stream else { return };

                    let Ok(_) = stream.set_write_timeout(Some(Duration::from_secs(10))) else { return };
                    let Ok(_) = stream.set_read_timeout(Some(Duration::from_secs(10))) else { return };

                    let Ok(addr) = stream.peer_addr() else { return };

                    let Some(mut stream) = AdoptedConnection::from_config(tls_config, stream) else { return };

                    Self::accept_stream(
                        config,
                        &mut stream,
                        addr,
                        true
                    );
                }
            });
        }

        Some(())
    }

    pub fn accept_stream(
        config: Arc<Config>, 
        stream: &mut (impl Read + Write + Closeable), 
        addr: SocketAddr,
        https: bool
    ) -> Option<()> {
        let mut reqst_data: Vec<u8> = vec![0; 4096];

        stream.read(&mut reqst_data).ok()?;

        let reqst = String::from_utf8(reqst_data).ok()?;
        let reqst = reqst.trim_matches(char::from(0));

        let (head, body) = reqst.split_once("\r\n\r\n")?;

        let mut head_lines = head.split("\r\n");

        let status = head_lines.next()?;
        let status: Vec<&str> = status.split(" ").collect();

        let mut host: &str = "honk";
        let mut keep_alive: bool = false;
        let mut content_length: usize = 0;

        for l in head_lines {
            let (key, value) = l.split_once(": ")?;
            let key = key.to_lowercase().replace("-", "_");

            if key == "host" {
                host = &value;
            }
            if key == "connection" {
                keep_alive = value == "keep-alive";
            }
            if key == "content_length" {
                content_length = value.parse().ok()?;
            }
        }

        let site = config.get_site(host);

        if site.is_none() {
            return None;
        }

        let site = site?.clone();
        let mut site_stream = site.clone().connect()?;

        site_stream.write((addr.to_string() + "\n" + reqst).as_bytes()).ok()?;

        if content_length != 0 && content_length > body.len() {
            let mut body_data: Vec<u8> = Vec::new();
            stream.read_to_end(&mut body_data).ok()?;
            site_stream.write_all(&body_data).ok()?;
        }

        loop {
            let mut buf: Vec<u8> = Vec::new();
            site_stream.read_to_end(&mut buf).ok()?;
            if buf.is_empty() {
                break;
            }
            stream.write_all(&buf).ok()?;
        }

        let method = status[0];
        let page = status[1];

        if https {
            info!("{} > {} https://{}{}", addr.to_string(), method, host, page);
        } else {
            info!("{} > {} http://{}{}", addr.to_string(), method, host, page);
        }

        if keep_alive && site.enable_keep_alive {
            loop {
                if !site.support_keep_alive {
                    site_stream.shutdown(Shutdown::Both).ok()?;
                }

                let mut reqst_data: Vec<u8> = vec![0; 4096];

                stream.read(&mut reqst_data).ok()?;

                let reqst = String::from_utf8(reqst_data).ok()?;
                let reqst = reqst.trim_matches(char::from(0));

                let (head, body) = reqst.split_once("\r\n\r\n")?;

                let mut head_lines = head.split("\r\n");

                let status = head_lines.next()?;
                let status: Vec<&str> = status.split(" ").collect();

                let mut content_length: usize = 0;

                for l in head_lines {
                    let (key, value) = l.split_once(": ")?;
                    let key = key.to_lowercase().replace("-", "_");

                    if key == "content_length" {
                        content_length = value.parse().ok()?;
                    }
                }

                if !site.support_keep_alive {
                    site_stream = site.clone().connect()?
                }

                site_stream.write((addr.to_string() + "\n" + reqst).as_bytes()).ok()?;

                if content_length != 0 && content_length > body.len() {
                    let mut body_data: Vec<u8> = Vec::new();
                    stream.read_to_end(&mut body_data).ok()?;
                    site_stream.write_all(&body_data).ok()?;
                }

                loop {
                    let mut buf: Vec<u8> = Vec::new();
                    site_stream.read_to_end(&mut buf).ok()?;
                    if buf.is_empty() {
                        break;
                    }
                    stream.write_all(&buf).ok()?;
                }

                let method = status[0];
                let page = status[1];
        
                if https {
                    info!("{} > {} https://{}{}", addr.to_string(), method, host, page);
                } else {
                    info!("{} > {} http://{}{}", addr.to_string(), method, host, page);
                }
            }
        }

        site_stream.close();
        stream.close();

        Some(())
    }
}