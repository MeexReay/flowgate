use openssl::ssl::{SslContext, SslFiletype, SslMethod};

#[derive(Clone)]
pub struct SslCert {
    context: Option<SslContext>,
}

fn generate_ctx(cert_file: &str, key_file: &str) -> Option<SslContext> {
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

impl SslCert {
    pub fn new(cert_file: &str, key_file: &str) -> Option<SslCert> {
        Some(SslCert {
            context: match generate_ctx(cert_file, key_file) {
                Some(i) => Some(i),
                None => {
                    return None;
                }
            }
        })
    }

    pub fn get_context(&self) -> SslContext {
        self.context.as_ref().unwrap().clone()
    }
}