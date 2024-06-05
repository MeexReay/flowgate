use http_rrs::ThreadPool;
use log::{debug, info, warn};
use openssl::ssl::{
    NameType, SniError, SslAcceptor, SslAlert, SslContext, SslFiletype, SslMethod, SslRef,
    SslStream,
};
use std::time::Duration;
use std::{
    io::{Read, Write},
    net::{IpAddr, Shutdown, TcpListener, TcpStream},
    sync::Arc,
    thread,
};

#[derive(Clone)]
pub struct SslCert {
    pub cert_file: String,
    pub key_file: String,
    pub ctx_index: u8,
    pub ctx: Option<SslContext>,
}

impl SslCert {
    pub fn generate_ctx(cert_file: &str, key_file: &str) -> Option<SslContext> {
        let mut ctx = match SslContext::builder(SslMethod::tls()) {
            Ok(i) => i,
            Err(_) => return None,
        };
        match ctx.set_private_key_file(&key_file, SslFiletype::PEM) {
            Ok(i) => i,
            Err(_) => return None,
        };
        match ctx.set_certificate_file(&cert_file, SslFiletype::PEM) {
            Ok(i) => i,
            Err(_) => return None,
        };
        match ctx.check_private_key() {
            Ok(i) => i,
            Err(_) => return None,
        };
        Some(ctx.build())
    }

    pub fn new(cert_file: &str, key_file: &str) -> Option<SslCert> {
        let ctx = match Self::generate_ctx(cert_file, key_file) {
            Some(i) => Some(i),
            None => {
                return None;
            }
        };

        Some(SslCert {
            ctx: ctx,
            cert_file: cert_file.to_string(),
            key_file: key_file.to_string(),
            ctx_index: 0,
        })
    }

    pub fn get_ctx(&mut self) -> Option<&SslContext> {
        // self.ctx_index += 1;
        // if self.ctx_index > 5 {
        //     self.ctx_index = 0;
        //     self.ctx = Self::generate_ctx(&self.cert_file, &self.key_file);
        // }
        self.ctx.as_ref()
    }
}

#[derive(Clone)]
pub struct Site {
    pub domain: String,
    pub host: String,
    pub ssl: Option<SslCert>,
}

impl Site {
    fn connect(self) -> Result<TcpStream, String> {
        match TcpStream::connect(self.host) {
            Ok(i) => Ok(i),
            Err(_) => Err("server not canacting".to_string()),
        }
    }
}

#[derive(Clone)]
pub struct SiteServer {
    host: String,
    sites: Arc<Vec<Site>>,
}

fn split_once<'a>(in_string: &'a str, separator: &str) -> Result<(&'a str, &'a str), String> {
    let mut splitter = in_string.splitn(2, &separator);
    let first = match splitter.next() {
        Some(i) => i,
        None => return Err("first split nat foined".to_string()),
    };
    let second = match splitter.next() {
        Some(i) => i,
        None => return Err("escond split nat foined".to_string()),
    };
    Ok((first, second))
}

fn get_site(sites: &Vec<Site>, domain: &str) -> Option<Site> {
    for i in sites.iter() {
        if i.domain == domain {
            return Some(i.clone());
        }
    }
    return None;
}

impl SiteServer {
    pub fn new<'a>(host: String, sites: Arc<Vec<Site>>) -> Self {
        SiteServer { host, sites }
    }

    fn get_site(self, domain: &str) -> Option<Site> {
        return get_site(&self.sites, domain);
    }
}

impl SiteServer {
    pub fn start_http(self) {
        thread::spawn(move || {
            self.run_http();
        });
    }

    pub fn run_http(self) {
        let listener: TcpListener = match TcpListener::bind(&self.host) {
            Ok(i) => i,
            Err(_) => {
                info!("Http server listener bind error");
                return;
            }
        };
        let pool = ThreadPool::new(10);

        info!("HTTP server runned on {}", &self.host);

        for stream in listener.incoming() {
            let local_self = self.clone();

            pool.execute(move || {
                let mut stream = match stream {
                    Ok(i) => i,
                    Err(e) => {
                        warn!("{}", e);
                        return;
                    }
                };

                match stream.set_write_timeout(Some(Duration::from_secs(10))) {
                    Ok(i) => i,
                    Err(_) => {
                        return;
                    }
                };
                match stream.set_read_timeout(Some(Duration::from_secs(10))) {
                    Ok(i) => i,
                    Err(_) => {
                        return;
                    }
                };

                let addr = stream.peer_addr();

                match local_self.accept_http(
                    &mut stream,
                    match addr {
                        Ok(v) => v,
                        Err(_) => {
                            return;
                        }
                    },
                ) {
                    Ok(v) => {
                        let (addr, method, host, page) = v;
                        info!("{} > {} http://{}{}", addr, method, host, page);
                    }
                    Err(_) => {}
                }
            });
        }
    }

    pub fn run_ssl(self) {
        let listener: TcpListener = match TcpListener::bind(&self.host) {
            Ok(i) => i,
            Err(_) => {
                info!("Ssl server listener bind error");
                return;
            }
        };

        let mut cert = match SslAcceptor::mozilla_intermediate(SslMethod::tls()) {
            Ok(v) => v,
            Err(_) => {
                info!("Ssl acceptor create error");
                return;
            }
        };

        let sites = self.clone().sites.clone();

        cert.set_servername_callback(Box::new(
            move |_ssl: &mut SslRef, _alert: &mut SslAlert| -> Result<(), SniError> {
                debug!("hangs");
                let servname = match _ssl.servername(NameType::HOST_NAME) {
                    Some(i) => i,
                    None => return Err(SniError::NOACK),
                };
                let cert = match get_site(&sites, servname) {
                    Some(i) => i,
                    None => return Err(SniError::NOACK),
                };
                match _ssl.set_ssl_context(
                    match match cert.ssl {
                        Some(i) => i,
                        None => return Err(SniError::NOACK),
                    }
                    .get_ctx()
                    {
                        Some(k) => k,
                        None => return Err(SniError::NOACK),
                    },
                ) {
                    Ok(i) => i,
                    Err(_) => return Err(SniError::NOACK),
                };
                return Ok(());
            },
        ));

        let cert = cert.build();

        let pool = ThreadPool::new(10);

        info!("HTTPS server runned on {}", &self.host);

        for stream in listener.incoming() {
            let local_self = self.clone();
            let local_cert = cert.clone();

            pool.execute(move || {
                let stream = match stream {
                    Ok(i) => {
                        debug!("norm esy");
                        i
                    }
                    Err(_) => {
                        return;
                    }
                };

                match stream.set_write_timeout(Some(Duration::from_secs(10))) {
                    Ok(i) => i,
                    Err(_) => {
                        return;
                    }
                };
                match stream.set_read_timeout(Some(Duration::from_secs(10))) {
                    Ok(i) => i,
                    Err(_) => {
                        return;
                    }
                };

                let addr = stream.peer_addr();

                let mut stream = match local_cert.accept(stream) {
                    Ok(st) => {
                        debug!("ssl esy");
                        st
                    }
                    Err(_) => {
                        return;
                    }
                };

                match local_self.accept_ssl(
                    &mut stream,
                    match addr {
                        Ok(v) => v,
                        Err(_) => {
                            return;
                        }
                    },
                ) {
                    Ok(v) => {
                        let (addr, method, host, page) = v;
                        info!("{} > {} https://{}{}", addr, method, host, page);
                    }
                    Err(_) => {}
                }
            });
        }
    }

    pub fn accept_http(
        self,
        stream: &mut TcpStream,
        peer_addr: std::net::SocketAddr,
    ) -> Result<(String, String, String, String), ()> {
        let octets = match peer_addr.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => [127, 0, 0, 1],
        };

        let dot: String = String::from(".");
        let ip_str = String::from(
            octets[0].to_string()
                + &dot
                + &octets[1].to_string()
                + &dot
                + &octets[2].to_string()
                + &dot
                + &octets[3].to_string(),
        );

        println!("{}", &ip_str);

        let addition: String = ip_str.clone() + ":" + peer_addr.port().to_string().as_str() + "\n";

        let mut reqst_data: Vec<u8> = vec![0; 4096];

        match stream.read(&mut reqst_data) {
            Ok(i) => i,
            Err(_) => return Err(()),
        };

        let reqst = match String::from_utf8(reqst_data) {
            Ok(v) => v,
            Err(_) => {
                return Err(());
            }
        };
        let reqst = reqst.trim_matches(char::from(0));

        let (head, body) = match split_once(&reqst, "\r\n\r\n") {
            Ok(i) => i,
            Err(_) => return Err(()),
        };

        let mut head_lines = head.split("\r\n");

        let status = match head_lines.next() {
            Some(i) => i,
            None => return Err(()),
        };
        let status: Vec<&str> = status.split(" ").collect();

        let mut host: &str = "honk";
        let mut content_length: usize = 0;

        for l in head_lines {
            let (key, value) = match split_once(&l, ": ") {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
            let key = key.to_lowercase().replace("-", "_");

            if key == "host" {
                host = &value;
            }
            if key == "content_length" {
                content_length = match value.parse() {
                    Ok(i) => i,
                    Err(_) => {
                        return Err(());
                    }
                };
            }
        }

        let site = self.get_site(host);

        if site.is_none() {
            return Err(());
        }

        let site = match site {
            Some(i) => i,
            None => return Err(()),
        };
        let mut site_stream = match site.connect() {
            Ok(i) => i,
            Err(_) => return Err(()),
        };

        match site_stream.write((addition + reqst).as_bytes()) {
            Ok(i) => i,
            Err(_) => {
                return Err(());
            }
        };

        let body_len = body.len();
        if body_len < content_length {
            let mut body_data: Vec<u8> = vec![0; content_length - body_len];
            match stream.read_exact(&mut body_data) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
            match site_stream.write_all(&body_data) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
        }

        loop {
            let mut buf: Vec<u8> = Vec::new();
            match site_stream.read_to_end(&mut buf) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
            if buf.is_empty() {
                break;
            }
            match stream.write_all(&buf) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
        }

        let method = status[0];
        let page = status[1];

        match site_stream.shutdown(Shutdown::Both) {
            Ok(i) => i,
            Err(_) => {
                return Err(());
            }
        };

        Ok((
            ip_str.clone(),
            method.to_string().clone(),
            host.to_string().clone(),
            page.to_string().clone(),
        ))
    }

    pub fn accept_ssl(
        self,
        stream: &mut SslStream<TcpStream>,
        peer_addr: std::net::SocketAddr,
    ) -> Result<(String, String, String, String), ()> {
        let octets = match peer_addr.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => [127, 0, 0, 1],
        };

        let dot: String = String::from(".");
        let ip_str = String::from(
            octets[0].to_string()
                + &dot
                + &octets[1].to_string()
                + &dot
                + &octets[2].to_string()
                + &dot
                + &octets[3].to_string(),
        );

        let addition: String = ip_str.clone() + ":" + peer_addr.port().to_string().as_str() + "\n";

        let mut reqst_data: Vec<u8> = vec![0; 4096];

        match stream.read(&mut reqst_data) {
            Ok(i) => i,
            Err(_) => return Err(()),
        };

        let reqst = match String::from_utf8(reqst_data) {
            Ok(v) => v,
            Err(_) => {
                return Err(());
            }
        };
        let reqst = reqst.trim_matches(char::from(0));

        let (head, body) = match split_once(&reqst, "\r\n\r\n") {
            Ok(i) => i,
            Err(_) => return Err(()),
        };

        let mut head_lines = head.split("\r\n");

        let status = match head_lines.next() {
            Some(i) => i,
            None => return Err(()),
        };
        let status: Vec<&str> = status.split(" ").collect();

        let mut host: &str = "honk";
        let mut content_length: usize = 0;

        for l in head_lines {
            let (key, value) = match split_once(&l, ": ") {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
            let key = key.to_lowercase().replace("-", "_");

            if key == "host" {
                host = &value;
            }
            if key == "content_length" {
                content_length = match value.parse() {
                    Ok(i) => i,
                    Err(_) => {
                        return Err(());
                    }
                };
            }
        }

        let site = self.get_site(host);

        if site.is_none() {
            return Err(());
        }

        let site = match site {
            Some(i) => i,
            None => return Err(()),
        };
        let mut site_stream = match site.connect() {
            Ok(i) => i,
            Err(_) => return Err(()),
        };

        match site_stream.write((addition + reqst).as_bytes()) {
            Ok(i) => i,
            Err(_) => {
                return Err(());
            }
        };

        let body_len = body.len();
        if body_len < content_length {
            let mut body_data: Vec<u8> = vec![0; content_length - body_len];
            match stream.read_exact(&mut body_data) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
            match site_stream.write_all(&body_data) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
        }

        loop {
            let mut buf: Vec<u8> = Vec::new();
            match site_stream.read_to_end(&mut buf) {
                Ok(i) => i,
                Err(_) => return Err(()),
            };
            if buf.is_empty() {
                break;
            }
            match stream.write_all(&buf) {
                Ok(i) => i,
                Err(e) => {
                    info!("{}", e);
                    return Err(());
                }
            };
        }

        let method = status[0];
        let page = status[1];

        match site_stream.shutdown(Shutdown::Both) {
            Ok(i) => i,
            Err(_) => {
                return Err(());
            }
        };

        Ok((
            ip_str.clone(),
            method.to_string().clone(),
            host.to_string().clone(),
            page.to_string().clone(),
        ))
    }
}
