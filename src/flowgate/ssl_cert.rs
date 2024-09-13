use openssl::ssl::{SslContext, SslFiletype, SslMethod};

#[derive(Clone)]
pub struct SslCert {
    context: Option<SslContext>,
}

fn generate_ctx(cert_file: &str, key_file: &str) -> Option<SslContext> {
    let mut ctx = SslContext::builder(SslMethod::tls()).ok()?;
    ctx.set_private_key_file(&key_file, SslFiletype::PEM).ok()?;
    ctx.set_certificate_file(&cert_file, SslFiletype::PEM).ok()?;
    ctx.check_private_key().ok()?;
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