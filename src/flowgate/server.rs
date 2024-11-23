use std::{
    io::{Read, Write}, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream}, str::FromStr, sync::{Arc, RwLock}, thread, time::Duration
};

use log::info;
use threadpool::ThreadPool;

use super::{closeable::Closeable, config::{Config,SiteConfig,IpForwarding}};

pub struct FlowgateServer {
    config: Arc<RwLock<Config>>,
}

impl FlowgateServer {
    pub fn new(config: Arc<RwLock<Config>>) -> Self {
        FlowgateServer { config }
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
        config: Arc<RwLock<Config>>
    ) -> Option<()> {
        let listener = TcpListener::bind(&config.read().ok()?.http_host).ok()?;

        let pool = ThreadPool::new(10);

        info!("HTTP server runned on {}", &config.read().ok()?.http_host);

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
        config: Arc<RwLock<Config>>
    ) -> Option<()> {
        use openssl::ssl::{NameType, SniError, SslAcceptor, SslAlert, SslMethod, SslRef};

        let listener = TcpListener::bind(&config.read().ok()?.https_host).ok()?;

        let mut cert = SslAcceptor::mozilla_intermediate(SslMethod::tls()).ok()?;

        cert.set_servername_callback(Box::new({
                let config = config.clone();

                move |ssl: &mut SslRef, _: &mut SslAlert| -> Result<(), SniError> {
                    let servname = ssl.servername(NameType::HOST_NAME).ok_or(SniError::NOACK)?;
                    let c = config.read().unwrap();
                    let cert = c.get_site(servname).ok_or(SniError::NOACK)?;
                    ssl.set_ssl_context(&cert.ssl.as_ref().ok_or(SniError::NOACK)?.get_context()).ok().ok_or(SniError::NOACK)
                }
            }
        ));

        let cert = cert.build();

        let pool = ThreadPool::new(config.read().ok()?.threadpool_size);

        info!("HTTPS server runned on {}", &config.read().ok()?.https_host);

        for stream in listener.incoming() {
            pool.execute({
                let config = config.clone();
                let cert = cert.clone();

                move || {
                    let Ok(stream) = stream else { return };
                    
                    let Ok(_) = stream.set_write_timeout(Some(config.read().unwrap().connection_timeout)) else { return };
                    let Ok(_) = stream.set_read_timeout(Some(config.read().unwrap().connection_timeout)) else { return };

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
        config: Arc<RwLock<Config>>
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
        config: Arc<RwLock<Config>>, 
        stream: &mut (impl Read + Write + Closeable), 
        addr: SocketAddr,
        https: bool
    ) -> Option<()> {
        let mut conn = Self::read_request(config.clone(), stream, addr, https, None)?;

        if conn.2 && conn.1.enable_keep_alive {
            loop {
                if !conn.1.support_keep_alive {
                    conn.0.close();
                    conn.0 = conn.1.connect()?;
                }
                conn = Self::read_request(config.clone(), stream, addr, https, Some(conn))?;
            }
        }

        conn.0.close();
        stream.close();

        Some(())
    }

    fn read_request<'a>(
        config: Arc<RwLock<Config>>, 
        stream: &'a mut (impl Read + Write + Closeable), 
        addr: SocketAddr,
        https: bool,
        conn: Option<(TcpStream, SiteConfig, bool, String)>
    ) -> Option<(TcpStream, SiteConfig, bool, String)> {
        let mut addr = addr;

        match &config.read().ok()?.incoming_ip_forwarding {
            IpForwarding::Simple => {
                let mut header = Vec::new();

                {
                    let mut buf = [0; 1];

                    while let Ok(1) = stream.read(&mut buf) {
                        let byte = buf[0];
                        if byte == b'\n' { break }
                        header.push(byte);
                    }
                }

                addr = SocketAddr::from_str(&String::from_utf8(header).ok()?).ok()?;
            },
            IpForwarding::Modern => {
                let mut ipver = [0; 1];
                stream.read(&mut ipver).ok()?;
                addr = match ipver[0] {
                    0x01 => {
                        let mut octets = [0; 4];
                        stream.read(&mut octets).ok()?;
                        let mut port = [0; 2];
                        stream.read(&mut port).ok()?;
                        let port = u16::from_be_bytes(port);
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
                    }, 0x02 => {
                        let mut octets = [0; 16];
                        stream.read(&mut octets).ok()?;
                        let mut port = [0; 2];
                        stream.read(&mut port).ok()?;
                        let port = u16::from_be_bytes(port);
                        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0))
                    }, _ => { return None },
                };
            },
            _ => { }
        }

        let mut head = Vec::new();

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
        
        if let IpForwarding::Header(header) = &config.read().ok()?.incoming_ip_forwarding {
            if let Some(ip) = headers.iter().find(|o| o.0 == header).map(|o| o.1) {
                addr = SocketAddr::from_str(ip).ok()?;
            }
        }

        let mut conn: (TcpStream, SiteConfig, bool, String) = if conn.is_none() {
            let mut host = String::new();
            let mut keep_alive = false;

            for (key, value) in &headers {
                match key.to_lowercase().as_str() {
                    "host" => host = value.to_string(),
                    "connection" => keep_alive = *value == "keep-alive",
                    _ => {}
                }
            }

            let site = config.read().ok()?.get_site(&host)?.clone();

            (site.connect()?, site, keep_alive, host)
        } else {
            conn?
        };
        
        let content_length = headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "content-length")
            .next()
            .map(|o| o.1.parse().ok())
            .flatten()
            .unwrap_or(0usize);

        let mut reqbuf: Vec<u8> = Vec::new();

        if let Some(replace_host) = conn.1.replace_host.clone() {
            let mut new_head = Vec::new();
            let mut is_status = true;

            for line in head_str.split("\r\n") {
                if is_status {
                    new_head.append(&mut line.as_bytes().to_vec());
                    is_status = false;
                } else {
                    new_head.append(&mut b"\r\n".to_vec());
                    let (key, _) = line.split_once(": ")?;
                    if key.to_lowercase() == "host" {
                        new_head.append(&mut key.as_bytes().to_vec());
                        new_head.append(&mut b": ".to_vec());
                        new_head.append(&mut replace_host.as_bytes().to_vec());
                    } else {
                        new_head.append(&mut line.as_bytes().to_vec());
                    }
                }
            }

            head = new_head;
        }

        match &conn.1.ip_forwarding {
            IpForwarding::Header(header) => {
                reqbuf.append(&mut status.to_string().as_bytes().to_vec());
                reqbuf.append(&mut b"\r\n".to_vec());
                for (key, value) in &headers {
                    if *key == header { continue }
                    reqbuf.append(&mut key.to_string().as_bytes().to_vec());
                    reqbuf.append(&mut b": ".to_vec());
                    reqbuf.append(&mut value.to_string().as_bytes().to_vec());
                    reqbuf.append(&mut b"\r\n".to_vec());
                }
                reqbuf.append(&mut header.as_bytes().to_vec());
                reqbuf.append(&mut b": ".to_vec());
                reqbuf.append(&mut addr.to_string().as_bytes().to_vec());
                reqbuf.append(&mut b"\r\n\r\n".to_vec());
            },
            IpForwarding::Simple => {
                reqbuf.append(&mut addr.to_string().as_bytes().to_vec());
                reqbuf.push(b'\n');
                reqbuf.append(&mut head.clone());
                reqbuf.append(&mut b"\r\n\r\n".to_vec());
            },
            IpForwarding::Modern => {
                reqbuf.push(if addr.is_ipv4() { 0x01 } else { 0x02 });
                match addr.ip() {
                    IpAddr::V4(ip) => {
                        reqbuf.append(&mut ip.octets().to_vec());
                    }, IpAddr::V6(ip) => {
                        reqbuf.append(&mut ip.octets().to_vec());
                    }
                }
                reqbuf.append(&mut addr.port().to_be_bytes().to_vec());
                reqbuf.append(&mut head.clone());
                reqbuf.append(&mut b"\r\n\r\n".to_vec());
            },
            IpForwarding::None => {
                reqbuf.append(&mut head.clone());
                reqbuf.append(&mut b"\r\n\r\n".to_vec());
            }
        }

        conn.0.write_all(&reqbuf).ok()?;

        if content_length > 0 {
            let mut read = 0usize;
            let mut buf = vec![0; 4096];
            while let Ok(size) = stream.read(&mut buf) {
                if size == 0 { break }
                read += size;
                buf.truncate(size);
                conn.0.write_all(&buf).ok()?;
                buf = vec![0; 4096];
                if read == content_length { break }
            }
        }

        if conn.1.support_keep_alive {
            let mut head = Vec::new();

            {
                let mut buf = [0; 1];
                let mut counter = 0;

                while let Ok(1) = conn.0.read(&mut buf) {
                    let byte = buf[0];
                    head.push(byte);

                    stream.write_all(&buf).ok()?;

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

            let content_length = head_str.split("\r\n")
                .skip(1)
                .filter(|l| l.contains(": "))
                .map(|l| l.split_once(": ").unwrap())
                .filter(|(k, _)| k.to_lowercase() == "content-length")
                .next()
                .map(|o| o.1.parse().ok())
                .flatten()
                .unwrap_or(0usize);

            if content_length > 0 {
                let mut read = 0usize;
                let mut buf = vec![0; 4096];
                while let Ok(size) = conn.0.read(&mut buf) {
                    if size == 0 { break }
                    read += size;
                    buf.truncate(size);
                    stream.write_all(&buf).ok()?;
                    buf = vec![0; 4096];
                    if read == content_length { break }
                }
            }
        } else {
            let mut buf = Vec::new();
            conn.0.read_to_end(&mut buf).ok()?;
            stream.write_all(&buf).ok()?;
        }

        info!("{addr} > {} {}://{}{}", status_seq[0], if https { "https" } else { "http" }, conn.3, status_seq[1]);

        Some(conn)
    }
}