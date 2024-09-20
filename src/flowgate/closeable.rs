use std::net::{Shutdown, TcpStream};

#[cfg(feature = "use-openssl")]
use openssl::ssl::SslStream;

pub trait Closeable {
    fn close(&self);
}

impl Closeable for TcpStream {
    fn close(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
}

#[cfg(feature = "use-openssl")]
impl<T: Closeable> Closeable for SslStream<T> {
    fn close(&self) {
        self.get_ref().close();
    }
}
