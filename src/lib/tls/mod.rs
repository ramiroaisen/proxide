pub mod cert_resolver;
pub mod danger_no_cert_verifier;

use bytes::Buf;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::{fs, path::Path};

#[cfg(not(feature = "ring"))]
pub use rustls::crypto::aws_lc_rs as crypto;

#[cfg(feature = "ring")]
pub use rustls::crypto::ring as crypto;

// #[cfg(all(feature = "ring", feature = "aws_lc_rs"))]
// compile_error!("feature \"ring\" and feature \"aws_lc_rs\" cannot be enabled at the same time");

pub fn load_certs<P: AsRef<Path>>(
  filename: P,
) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
  let filename = filename.as_ref();

  log::debug!("loading certificate file at {}", filename.display());

  // open certificates file.
  let certfile = fs::File::open(filename)?;
  let mut reader = io::BufReader::new(certfile);

  // load and return certificates.
  let mut certs = vec![];

  for cert in rustls_pemfile::certs(&mut reader) {
    let cert = cert?;
    certs.push(cert);
  }

  log::debug!(
    "certificate file at {} loaded, obtained {} certificates",
    filename.display(),
    certs.len()
  );

  Ok(certs)
}

pub fn load_private_key<P: AsRef<Path>>(
  filename: P,
) -> Result<PrivateKeyDer<'static>, std::io::Error> {
  let filename = filename.as_ref();

  log::debug!("loading private key file at {}", filename.display());

  // let keyfile = fs::File::open(filename.as_ref())?;
  // The above line will fail silently if the user does not have read permissions on the file
  // so we read the full file contents into memory and then parse it, that way we can fail fast
  let keyfile = std::fs::read(filename)?;
  log::debug!("private key file at {} read", filename.display());

  let mut reader = io::BufReader::new(keyfile.reader());
  let key = match rustls_pemfile::private_key(&mut reader)? {
    Some(key) => key,
    None => {
      return Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "No private key found",
      ))
    }
  };

  log::debug!("private key file at {} parsed", filename.display());

  Ok(key)
}
