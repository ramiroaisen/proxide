use crate::client::pool::{ClientError, ClientErrorKind};
use hyper::{header::CONTENT_TYPE, http::uri::InvalidUri, Response};

use super::header::TEXT_PLAIN;
use crate::body::Body;

#[derive(Debug, thiserror::Error)]
pub enum ProxyHttpError {
  #[error("no host in request")]
  NoHost,

  #[error("invalid host in request")]
  InvalidHost,

  #[error("invalid upstream url, missing host")]
  InvalidUpstreamUrlMissingHost,

  #[error("could not parse url")]
  UrlParse(#[from] InvalidUri),

  #[error("upstream url missing domain")]
  UpstreamUrlMissingDomain,

  #[error("invalid header interpolation: {0}")]
  InvalidHeaderInterpolation(String),

  #[error("io error: {0}")]
  Io(#[from] std::io::Error),

  #[error("hyper server error: {0}")]
  HyperServer(#[from] hyper::Error),

  #[error("hyper client error: {0}")]
  HyperClient(#[from] hyper_util::client::legacy::Error),

  #[error("invalid redirect status: {0}")]
  InvalidRedirectStatus(u16),

  #[error("invalid redirect location: {0}")]
  InvalidRedirectLocation(String),

  #[error("could not resolve proxy target")]
  UnresolvedApp,

  #[error("could not resolve proxy target")]
  UnresolvedUpstream,

  #[error("could not resolve proxy target")]
  UnresolvedLocation,

  #[error("client error: {message}")]
  Client {
    kind: ClientErrorKind,
    message: String,
  },
}

impl From<ClientError> for ProxyHttpError {
  fn from(e: ClientError) -> Self {
    Self::Client {
      kind: e.kind(),
      message: e.to_string(),
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyStreamError {
  #[error("unresolvable upstream")]
  UnresolvableUpstream,
  #[error("unsupported scheme: {0}")]
  UnsupportedScheme(String),
  #[error("url missing domain")]
  UrlMissingDomain,
  #[error("url missing port")]
  UrlMissingPort,
  #[error("invalid server name")]
  InvalidServerName(#[from] rustls::pki_types::InvalidDnsNameError),
  #[error("proxy protocol read error: {0}")]
  ProxyProtocolRead(crate::proxy_protocol::ProxyProtocolError),
  #[error("proxy protocol write error: {0}")]
  ProxyProtocolEncode(crate::proxy_protocol::ProxyProtocolError),
  #[error("proxy protocol write timeout elapsed")]
  ProxyProtocolWriteTimeout,
  #[error("proxy protocol write error: {0}")]
  ProxyProtocolWrite(std::io::Error),
  #[error("write readed buf error: {0}")]
  WriteReadedBuf(std::io::Error),
  #[error("tcp connect error: {0}")]
  TcpConnect(std::io::Error),
  #[error("tls connect error: {0}")]
  TlsConnect(std::io::Error),
  #[error("copy bidirectional error: {0}")]
  Copy(std::io::Error),
  // #[error("server write error: {0}")]
  // ServerWrite(std::io::Error),
  // #[error("proxy read error: {0}")]
  // ProxyRead(std::io::Error),
  // #[error("proxy write error: {0}")]
  // ProxyWrite(std::io::Error),
}

impl ProxyHttpError {
  pub fn to_response(self) -> Response<Body> {
    let body = format!("{} - {:?}", self, self);
    let body = Body::full(body);
    let mut res = Response::new(body);
    *res.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
    res.headers_mut().append(CONTENT_TYPE, TEXT_PLAIN);
    res
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[allow(unused)]
  trait AssertSend: Send {}
  impl AssertSend for ProxyHttpError {}

  #[allow(unused)]
  trait AssertSync: Sync {}
  impl AssertSync for ProxyHttpError {}
}
