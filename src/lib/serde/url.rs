use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt::Display, ops::Deref};
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct HttpUpstreamBaseUrl(Url);

// crate::newtype!(HttpUpstreamBaseUrl => Url);
crate::json_schema_as!(HttpUpstreamBaseUrl => Url);

impl Display for HttpUpstreamBaseUrl {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.0.fmt(f)
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
    match url.scheme() {
      "http" | "https" => {}
      other => return Err(HttpUpstreamBaseUrlError::InvalidScheme(other.to_string())),
    };

    if url.host().is_none() {
      return Err(HttpUpstreamBaseUrlError::MissingHost);
    }

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

    Ok(Self(url))
  }
}

impl Deref for HttpUpstreamBaseUrl {
  type Target = Url;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl From<HttpUpstreamBaseUrl> for Url {
  fn from(me: HttpUpstreamBaseUrl) -> Self {
    me.0
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
pub struct StreamUpstreamOrigin(Url);

impl StreamUpstreamOrigin {
  pub fn port(&self) -> u16 {
    self.0.port().unwrap()
  }

  pub fn host(&self) -> Host<&str> {
    self.0.host().unwrap()
  }

  pub fn scheme(&self) -> StreamUpstreamScheme {
    match self.0.scheme() {
      "tcp" => StreamUpstreamScheme::Tcp,
      "ssl" => StreamUpstreamScheme::Ssl,
      "tls" => StreamUpstreamScheme::Tls,
      _ => unreachable!(),
    }
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
    match url.scheme() {
      "tcp" | "ssl" | "tls" => {}
      other => return Err(StreamUpstreamOriginError::InvalidScheme(other.to_string())),
    };

    if url.host().is_none() {
      return Err(StreamUpstreamOriginError::MissingHost);
    }

    if url.port().is_none() {
      return Err(StreamUpstreamOriginError::MissingPort);
    }

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

    Ok(Self(url))
  }
}

impl Deref for StreamUpstreamOrigin {
  type Target = Url;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl From<StreamUpstreamOrigin> for Url {
  fn from(me: StreamUpstreamOrigin) -> Self {
    me.0
  }
}

impl Display for StreamUpstreamOrigin {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.0.fmt(f)
  }
}

impl<'de> Deserialize<'de> for StreamUpstreamOrigin {
  fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    Url::deserialize(deserializer)?
      .try_into()
      .map_err(serde::de::Error::custom)
  }
}
