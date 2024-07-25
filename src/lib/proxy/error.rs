use crate::client::upstream_pool::{ClientError, ClientErrorKind};
use http::StatusCode;
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
  UpstreamUrlParse(#[source] InvalidUri),

  #[error("upstream url missing domain")]
  UpstreamUrlMissingDomain,

  #[error("hyper server error: {0}")]
  IncomingBody(#[source] hyper::Error),

  #[error("could not resolve proxy target")]
  UnresolvedApp,

  #[error("could not resolve proxy target")]
  UnresolvedUpstream,

  #[error("could not resolve proxy target")]
  UnresolvedLocation,

  #[error("invalid header after interpolation: {0}")]
  InvalidHeaderInterpolation(String),

  #[error("compress body chunk error: {0}")]
  CompressBodyChunk(#[source] std::io::Error),

  #[error("io error after upgrade (client): {0}")]
  UpgradeIoClient(#[source] hyper::Error),

  #[error("io error after upgrade (upstream): {0}")]
  UpgradeIoUpstream(#[source] hyper::Error),

  #[error("io error after upgrade (both), client: {client} - upstream: {upstream}")]
  UpgradeIoBoth {
    client: hyper::Error,
    upstream: hyper::Error,
  },

  #[error("client error: {message}")]
  Client {
    kind: ClientErrorKind,
    message: String,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorOriginator {
  User,
  Config,
  Upstream,
  Io,
  Internal,
}

impl ProxyHttpError {
  pub fn originator(&self) -> ErrorOriginator {
    use ProxyHttpError as E;
    match self {
      E::UnresolvedApp => ErrorOriginator::User,
      E::UnresolvedLocation => ErrorOriginator::User,
      E::UnresolvedUpstream => ErrorOriginator::User,
      E::NoHost => ErrorOriginator::User,
      E::InvalidHost => ErrorOriginator::User,
      E::UpstreamUrlParse(_) => ErrorOriginator::User,
      E::UpstreamUrlMissingDomain => ErrorOriginator::Config,
      E::InvalidUpstreamUrlMissingHost => ErrorOriginator::Config,
      E::InvalidHeaderInterpolation(_) => ErrorOriginator::Config,
      E::IncomingBody(_) => ErrorOriginator::Io,
      E::CompressBodyChunk(_) => ErrorOriginator::Io,
      E::UpgradeIoBoth { .. } => ErrorOriginator::Io,
      E::UpgradeIoClient(_) => ErrorOriginator::Io,
      E::UpgradeIoUpstream(_) => ErrorOriginator::Upstream,
      E::Client { kind, .. } => kind.originator(),
    }
  }

  pub fn status(&self) -> StatusCode {
    use ProxyHttpError as E;
    match self {
      E::UnresolvedApp => StatusCode::NOT_FOUND,
      E::UnresolvedLocation => StatusCode::NOT_FOUND,
      E::UnresolvedUpstream => StatusCode::NOT_FOUND,
      E::NoHost => StatusCode::BAD_REQUEST,
      E::InvalidHost => StatusCode::BAD_REQUEST,
      E::UpstreamUrlParse(_) => StatusCode::INTERNAL_SERVER_ERROR,
      E::UpstreamUrlMissingDomain => StatusCode::INTERNAL_SERVER_ERROR,
      E::InvalidHeaderInterpolation(_) => StatusCode::INTERNAL_SERVER_ERROR,
      E::InvalidUpstreamUrlMissingHost => StatusCode::INTERNAL_SERVER_ERROR,
      E::IncomingBody(_) => StatusCode::INTERNAL_SERVER_ERROR,
      E::CompressBodyChunk(_) => StatusCode::INTERNAL_SERVER_ERROR,
      E::UpgradeIoBoth { .. } => StatusCode::BAD_REQUEST,
      E::UpgradeIoClient(_) => StatusCode::BAD_REQUEST,
      E::UpgradeIoUpstream(_) => StatusCode::BAD_GATEWAY,
      E::Client { kind, .. } => kind.status(),
    }
  }
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

  #[error("tcp connect error: {0}")]
  TcpConnect(std::io::Error),

  #[error("tls connect error: {0}")]
  TlsConnect(std::io::Error),

  #[error("copy bidirectional error: {0}")]
  Copy(std::io::Error),
}

impl ProxyHttpError {
  pub fn to_response(self) -> Response<Body> {
    let body = format!(
      "{} {}\n{}",
      self.status().as_str(),
      self.status().canonical_reason().unwrap_or(""),
      self
    );
    let body = Body::full(body);
    let mut res = Response::new(body);
    *res.status_mut() = self.status();
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
