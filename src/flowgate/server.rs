use std::{
    io::{Read, Write}, 
    net::{SocketAddr, TcpListener, TcpStream}, 
    sync::Arc, 
    thread, 
    time::Duration
};

use log::info;
use threadpool::ThreadPool;

use crate::IpForwarding;

use super::{Closeable, Config, SiteConfig};

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
        // let mut head: Vec<u8> = Vec::new();

        // for char in stream.bytes() {
        //     if let Ok(char) = char {
        //         if char == b'\n' && &head[head.len()-3..] == b"\r\n\r" {
        //             head = head[..head.len()-3].to_vec();
        //             break;
        //         }
        //         head.push(char);
        //     } else {
        //         return None;
        //     }
        // }

        let mut connected = Self::read_request(config.clone(), stream, addr, https, None)?;

        if connected.2 && connected.1.enable_keep_alive {
            loop {
                if !connected.1.support_keep_alive {
                    connected.0.close();
                    connected.0 = connected.1.connect()?;
                }
                connected = Self::read_request(config.clone(), stream, addr, https, Some(connected))?;
            }
        }

        connected.0.close();
        stream.close();

        Some(())
    }

    fn read_request<'a>(
        config: Arc<Config>, 
        stream: &'a mut (impl Read + Write + Closeable), 
        addr: SocketAddr,
        https: bool,
        connected: Option<(TcpStream, SiteConfig, bool, String)>
    ) -> Option<(TcpStream, SiteConfig, bool, String)> {
        let mut head = Vec::with_capacity(4096);

        {
            let mut buf = [0; 1];
            let mut counter = 0;

            while let Ok(1) = stream.read(&mut buf) {
                let byte = buf[0];
                head.push(byte);

                counter = match (counter, byte) {
                    (0, b'\r') => 1,
                    (1, b'\n') => 2,
                    (2, b'\r') => 3,
                    (3, b'\n') => break,
                    _ => 0,
                };
            }

            head.truncate(head.len() - 4);
        }

        if head.is_empty() { return None; }
        
        let head_str = String::from_utf8(head.clone()).ok()?;
        let head_str = head_str.trim_matches(char::from(0));

        let mut head_lines = head_str.split("\r\n");

        let status = head_lines.next()?;
        let status_seq: Vec<&str> = status.split(" ").collect();

        let headers: Vec<(&str, &str)> = head_lines
            .filter(|l| l.contains(": "))
            .map(|l| l.split_once(": ").unwrap())
            .collect();

        let mut connected: (TcpStream, SiteConfig, bool, String) = if connected.is_none() {
            let mut host = String::new();
            let mut keep_alive = false;

            for (key, value) in &headers {
                match key.to_lowercase().as_str() {
                    "host" => host = value.to_string(),
                    "connection" => keep_alive = *value == "keep-alive",
                    _ => {}
                }
            }

            let site = config.get_site(&host)?;

            (site.connect()?, site.clone(), keep_alive, host)
        } else {
            connected?
        };

        let mut content_length = 0;

        for (key, value) in &headers {
            match key.to_lowercase().as_str() {
                "content-length" => content_length = value.parse().ok()?,
                _ => {}
            }
        }
        
        let mut reqbuf: Vec<u8> = Vec::new();

        match connected.1.ip_forwarding {
            IpForwarding::Header => {
                reqbuf.append(&mut status.to_string().as_bytes().to_vec());
                reqbuf.append(&mut b"\r\n".to_vec());
                for (key, value) in &headers {
                    if *key == "X-Real-IP" { continue }
                    reqbuf.append(&mut key.to_string().as_bytes().to_vec());
                    reqbuf.append(&mut b": ".to_vec());
                    reqbuf.append(&mut value.to_string().as_bytes().to_vec());
                    reqbuf.append(&mut b"\r\n".to_vec());
                }
                reqbuf.append(&mut b"X-Real-IP: ".to_vec());
                reqbuf.append(&mut addr.to_string().as_bytes().to_vec());
                reqbuf.append(&mut b"\r\n\r\n".to_vec());
            },
            IpForwarding::Simple => {
                reqbuf.append(&mut addr.to_string().as_bytes().to_vec());
                reqbuf.push(b'\n');
                reqbuf.append(&mut head.clone());
                reqbuf.append(&mut b"\r\n\r\n".to_vec());
            },
        }

        connected.0.write_all(&reqbuf).ok()?;

        if content_length > 0 {
            let mut buf = Vec::with_capacity(content_length);
            stream.read_exact(&mut buf).ok()?;
            connected.0.write_all(&buf).ok()?;
        }

        let mut buf = Vec::new();
        while let Ok(size) = connected.0.read_to_end(&mut buf) {
            if size == 0 { break }
            stream.write_all(&buf).ok()?;
            buf = Vec::new();
        }

        info!("{addr} > {} {}://{}{}", status_seq[0], if https { "https" } else { "http" }, connected.3, status_seq[1]);

        Some(connected)
    }
}