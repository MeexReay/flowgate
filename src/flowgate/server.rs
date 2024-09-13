use std::{io::{Read, Write}, net::{Shutdown, SocketAddr, TcpListener}, sync::Arc, thread, time::Duration};

use log::info;
use openssl::ssl::{NameType, SniError, SslAcceptor, SslAlert, SslMethod, SslRef};
use threadpool::ThreadPool;

use crate::Config;

pub struct FlowgateServer {
    config: Arc<Config>,
}

impl FlowgateServer {
    pub fn new(config: Config) -> Self {
        FlowgateServer { config: Arc::new(config) }
    }

    pub fn start(self) {
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
                        true
                    );
                }
            });
        }

        Some(())
    }

    pub fn run_https(
        config: Arc<Config>
    ) -> Option<()> {
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

        let pool = ThreadPool::new(10);

        info!("HTTPS server runned on {}", &config.https_host);

        for stream in listener.incoming() {
            pool.execute({
                let config = config.clone();
                let cert = cert.clone();

                move || {
                    let Ok(stream) = stream else { return };

                    let Ok(_) = stream.set_write_timeout(Some(Duration::from_secs(10))) else { return };
                    let Ok(_) = stream.set_read_timeout(Some(Duration::from_secs(10))) else { return };

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

    pub fn accept_stream(
        config: Arc<Config>, 
        stream: &mut (impl Read + Write), 
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
        let mut content_length: usize = 0;

        for l in head_lines {
            let (key, value) = l.split_once(": ")?;
            let key = key.to_lowercase().replace("-", "_");

            if key == "host" {
                host = &value;
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
        let mut site_stream = site.connect()?;

        site_stream.write((addr.to_string() + "\n" + reqst).as_bytes()).ok()?;

        let body_len = body.len();
        if body_len < content_length {
            let mut body_data: Vec<u8> = vec![0; content_length - body_len];
            stream.read_exact(&mut body_data).ok()?;
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

        site_stream.shutdown(Shutdown::Both).ok()?;

        if https {
            info!("{} > {} https://{}{}", addr.to_string(), method, host, page);
        } else {
            info!("{} > {} http://{}{}", addr.to_string(), method, host, page);
        }

        Some(())
    }
}