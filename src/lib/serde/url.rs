use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::Display;
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct HttpUpstreamBaseUrl {
  scheme: HttpUpstreamScheme,
  host: Host,
  port: Option<u16>,
  path: String,
}

impl HttpUpstreamBaseUrl {
  pub fn scheme(&self) -> HttpUpstreamScheme {
    self.scheme
  }

  pub fn host(&self) -> &Host {
    &self.host
  }

  pub fn port(&self) -> Option<u16> {
    self.port
  }

  pub fn port_or_default(&self) -> u16 {
    match self.port {
      Some(port) => port,
      None => match self.scheme {
        HttpUpstreamScheme::Http => 80,
        HttpUpstreamScheme::Https => 443,
      },
    }
  }

  pub fn path(&self) -> &str {
    &self.path
  }
}

// crate::newtype!(HttpUpstreamBaseUrl => Url);
crate::json_schema_as!(HttpUpstreamBaseUrl => Url);

impl Display for HttpUpstreamBaseUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}://{}", self.scheme(), self.host())?;
    if let Some(port) = self.port {
      write!(f, ":{}", port)?;
    }
    write!(f, "{}", self.path)?;
    Ok(())
  }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpUpstreamBaseUrlError {
  #[error("invalid http upstream base url, unknown scheme {0}")]
  InvalidScheme(String),
  #[error("invalid http upstream base url, missing host")]
  MissingHost,
  #[error("invalid http upstream base url, username is not supported")]
  UsernameNotSupported,
  #[error("invalid http upstream base url, password is not supported")]
  PasswordNotSupported,
  #[error("invalid http upstream base url, query is not supported")]
  QueryNotSupported,
  #[error("invalid http upstream base url, fragment is not supported")]
  FragmentNotSupported,
}

impl TryFrom<Url> for HttpUpstreamBaseUrl {
  type Error = HttpUpstreamBaseUrlError;

  fn try_from(url: Url) -> Result<Self, Self::Error> {
    let scheme = match url.scheme() {
      "http" => HttpUpstreamScheme::Http,
      "https" => HttpUpstreamScheme::Https,
      other => return Err(HttpUpstreamBaseUrlError::InvalidScheme(other.to_string())),
    };

    let host = match url.host() {
      Some(host) => host.to_owned(),
      None => return Err(HttpUpstreamBaseUrlError::MissingHost),
    };

    let port = url.port();

    let path = url.path().to_string();

    if !url.username().is_empty() {
      return Err(HttpUpstreamBaseUrlError::UsernameNotSupported);
    }

    if url.password().is_some() {
      return Err(HttpUpstreamBaseUrlError::PasswordNotSupported);
    }

    if url.query().is_some() {
      return Err(HttpUpstreamBaseUrlError::QueryNotSupported);
    }

    if url.fragment().is_some() {
      return Err(HttpUpstreamBaseUrlError::FragmentNotSupported);
    }

    Ok(Self {
      scheme,
      host,
      port,
      path,
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum HttpUpstreamScheme {
  Http,
  Https,
}

impl std::fmt::Display for HttpUpstreamScheme {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HttpUpstreamScheme::Http => write!(f, "http"),
      HttpUpstreamScheme::Https => write!(f, "https"),
    }
  }
}

impl From<HttpUpstreamBaseUrl> for Url {
  fn from(me: HttpUpstreamBaseUrl) -> Self {
    Url::parse(&format!(
      "{scheme}://{host}{port}{path}",
      scheme = me.scheme(),
      host = me.host(),
      port = match me.port() {
        None => String::new(),
        Some(port) => {
          // TODO: remove this allocation
          format!(":{}", port)
        }
      },
      path = me.path(),
    ))
    .unwrap()
  }
}

impl<'de> Deserialize<'de> for HttpUpstreamBaseUrl {
  fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    Url::deserialize(deserializer)?
      .try_into()
      .map_err(serde::de::Error::custom)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct StreamUpstreamOrigin {
  scheme: StreamUpstreamScheme,
  host: Host,
  port: u16,
}

impl StreamUpstreamOrigin {
  pub fn port(&self) -> u16 {
    self.port
  }

  pub fn host(&self) -> &Host<String> {
    &self.host
  }

  pub fn scheme(&self) -> StreamUpstreamScheme {
    self.scheme
  }
}

crate::json_schema_as!(StreamUpstreamOrigin => Url);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum StreamUpstreamScheme {
  Tls,
  Ssl,
  Tcp,
}

impl std::fmt::Display for StreamUpstreamScheme {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      StreamUpstreamScheme::Tls => write!(f, "tls"),
      StreamUpstreamScheme::Ssl => write!(f, "ssl"),
      StreamUpstreamScheme::Tcp => write!(f, "tcp"),
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum StreamUpstreamOriginError {
  #[error("invalid tcp upstream origin, unknown scheme {0}")]
  InvalidScheme(String),
  #[error("invalid tcp upstream origin, missing host")]
  MissingHost,
  #[error("invalid tcp upstream origin, missing port")]
  MissingPort,
  #[error("invalid tcp upstream origin, username is not supported")]
  UsernameNotSupported,
  #[error("invalid tcp upstream origin, password is not supported")]
  PasswordNotSupported,
  #[error("invalid tcp upstream origin, query is not supported")]
  QueryNotSupported,
  #[error("invalid tcp upstream origin, fragment is not supported")]
  FragmentNotSupported,
}

impl TryFrom<Url> for StreamUpstreamOrigin {
  type Error = StreamUpstreamOriginError;

  fn try_from(url: Url) -> Result<Self, Self::Error> {
    let scheme = match url.scheme() {
      "tcp" => StreamUpstreamScheme::Tcp,
      "ssl" => StreamUpstreamScheme::Ssl,
      "tls" => StreamUpstreamScheme::Tls,
      other => return Err(StreamUpstreamOriginError::InvalidScheme(other.to_string())),
    };

    let host = match url.host() {
      Some(host) => host.to_owned(),
      None => return Err(StreamUpstreamOriginError::MissingHost),
    };

    let port = match url.port() {
      Some(port) => port,
      None => return Err(StreamUpstreamOriginError::MissingPort),
    };

    if !url.username().is_empty() {
      return Err(StreamUpstreamOriginError::UsernameNotSupported);
    }

    if url.password().is_some() {
      return Err(StreamUpstreamOriginError::PasswordNotSupported);
    }

    if !url.path().is_empty() && url.path() != "/" {
      return Err(StreamUpstreamOriginError::QueryNotSupported);
    }

    if url.fragment().is_some() {
      return Err(StreamUpstreamOriginError::FragmentNotSupported);
    }

    Ok(Self { scheme, host, port })
  }
}

impl From<StreamUpstreamOrigin> for Url {
  fn from(me: StreamUpstreamOrigin) -> Self {
    Url::parse(&format!("{}://{}:{}", me.scheme, me.host, me.port)).unwrap()
  }
}

impl Display for StreamUpstreamOrigin {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
  }
}

impl<'de> Deserialize<'de> for StreamUpstreamOrigin {
  fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    Url::deserialize(deserializer)?
      .try_into()
      .map_err(serde::de::Error::custom)
  }
}
