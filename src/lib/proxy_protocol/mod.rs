use std::{pin::Pin, task::{Context, Poll}};
use futures::FutureExt;
use http::Uri;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioIo};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tower::Service;
use std::future::Future;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use crate::client::pool::ProxyProtocolConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ExpectProxyProtocol {
  #[serde(rename = "v1")]
  V1,
  #[serde(rename = "v2")]
  V2,
  #[serde(rename = "any-version")]
  Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolVersion {
  V1,
  V2,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolError {
  #[error("io error: {0}")]
  Io(#[from] std::io::Error),
  #[error("proxy protocol parse error: {0}")]
  Parse(#[from] ParseError),
  #[error("proxy protocol encode error: {0}")]
  Encode(proxy_header::Error),
}

/// maybe in the future we want to implement tlvs, for now we just ignore them
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ProxyHeader {
  // v1 only
  Unknown,
  // v2 only
  Unspecified,
  // v2 only
  Local,
  // v1 or v2
  Tcp4(Tcp4Addresses),
  // v1 or v2
  Tcp6(Tcp6Addresses),
  // v2 only
  Unix(UnixAddresses),
}

impl ProxyHeader {

  pub fn can_losslessly_convert_to_v1(&self) -> bool {
    match self {
      ProxyHeader::Unknown => true,
      ProxyHeader::Unspecified => false, // converted to unknown
      ProxyHeader::Local => false, // converted to unknown
      ProxyHeader::Tcp4(_) => true,
      ProxyHeader::Tcp6(_) => true,
      ProxyHeader::Unix(_) => false,
    }
  }

  pub fn source_addr(&self) -> Option<SocketAddr> {
    match self {
      ProxyHeader::Unknown => None,
      ProxyHeader::Unspecified => None,
      ProxyHeader::Local => None,
      ProxyHeader::Unix(_) => None,
      ProxyHeader::Tcp4(a) => Some(a.source()),
      ProxyHeader::Tcp6(a) => Some(a.source()),
    }
  }

  pub fn destination_addr(&self) -> Option<SocketAddr> {
    match self {
      ProxyHeader::Unknown => None,
      ProxyHeader::Unspecified => None,
      ProxyHeader::Local => None,
      ProxyHeader::Unix(_) => None,
      ProxyHeader::Tcp4(a) => Some(a.destination()),
      ProxyHeader::Tcp6(a) => Some(a.destination()),
    }
  }
}

#[derive(Debug, thiserror::Error)]
#[error("socket addresses are not from the same family")]
pub struct FamilyMismatch;

impl TryFrom<(SocketAddr, SocketAddr)> for ProxyHeader {

  type Error = FamilyMismatch;

  fn try_from(value: (SocketAddr, SocketAddr)) -> Result<Self, Self::Error> {
    
    let (remote_addr, local_addr) = value;
    
    match (remote_addr.ip(), local_addr.ip()) {
      (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
        Ok(ProxyHeader::Tcp4(
          Tcp4Addresses {
            source_address: source_ip,
            source_port: remote_addr.port(),
            destination_address: destination_ip,
            destination_port: local_addr.port(),
          }
        ))
      }

      (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
        Ok(ProxyHeader::Tcp6(
          Tcp6Addresses {
            source_address: source_ip,
            source_port: remote_addr.port(),
            destination_address: destination_ip,
            destination_port: local_addr.port(),
          }
        ))
      }

      _ => {
        Err(FamilyMismatch)
      }
    }
  }
}

impl TryFrom<proxy_header::ProxyHeader<'_>> for ProxyHeader {
  type Error = FamilyMismatch;

  fn try_from(header: proxy_header::ProxyHeader) -> Result<Self, Self::Error> {
    match header.proxied_address() {
      None => Ok(ProxyHeader::Unknown),
      Some(addr) => ProxyHeader::try_from((addr.source, addr.destination)),
    }
  }
}


// impl From<ppp::v1::Header<'_>> for ProxyHeader {
//   fn from(header: ppp::v1::Header<'_>) -> Self {
//     match header.addresses {
//       ppp::v1::Addresses::Unknown => ProxyHeader::Unknown,
//       ppp::v1::Addresses::Tcp4(a) => ProxyHeader::Tcp4(Tcp4Addresses {
//         source_address: a.source_address,
//         source_port: a.source_port,
//         destination_address: a.destination_address,
//         destination_port: a.destination_port,
//       }),
//       ppp::v1::Addresses::Tcp6(a) => ProxyHeader::Tcp6(Tcp6Addresses {
//         source_address: a.source_address,
//         source_port: a.source_port,
//         destination_address: a.destination_address,
//         destination_port: a.destination_port,
//       }),
//     }
//   }
// }

// impl From<ppp::v2::Header<'_>> for ProxyHeader {
//   fn from(header: ppp::v2::Header<'_>) -> Self {
//     match header.addresses {
//       ppp::v2::Addresses::Unspecified => impl From<ppp::v2::Header<'_>> for ProxyHeader {
//   fn from(header: ppp::v2::Header<'_>) -> Self {
//     match header.addresses {
//       ppp::v2::Addresses::Unspecified => ProxyHeader::Unspecified,
//       ppp::v2::Addresses::Unix(unix) => ProxyHeader::Unix(UnixAddresses {
//         source: unix.source,
//         destination: unix.destination,
//       }),
//       ppp::v2::Addresses::IPv4(addrs) => ProxyHeader::Tcp4(Tcp4Addresses {
//         source_address: addrs.source_address,
//         source_port: addrs.source_port,
//         destination_address: addrs.destination_address,
//         destination_port: addrs.destination_port,
//       }),
//       ppp::v2::Addresses::IPv6(addrs) => ProxyHeader::Tcp6(Tcp6Addresses {
//         source_address: addrs.source_address,
//         source_port: addrs.source_port,
//         destination_address: addrs.destination_address,
//         destination_port: addrs.destination_port,
//       }),
//     }
//   }
// }ProxyHeader::Unspecified,
//       ppp::v2::Addresses::Unix(unix) => ProxyHeader::Unix(UnixAddresses {
//         source: unix.source,
//         destination: unix.destination,
//       }),
//       ppp::v2::Addresses::IPv4(addrs) => ProxyHeader::Tcp4(Tcp4Addresses {
//         source_address: addrs.source_address,
//         source_port: addrs.source_port,
//         destination_address: addrs.destination_address,
//         destination_port: addrs.destination_port,
//       }),
//       ppp::v2::Addresses::IPv6(addrs) => ProxyHeader::Tcp6(Tcp6Addresses {
//         source_address: addrs.source_address,
//         source_port: addrs.source_port,
//         destination_address: addrs.destination_address,
//         destination_port: addrs.destination_port,
//       }),
//     }
//   }
// }

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Tcp4Addresses {
  pub source_address: Ipv4Addr,
  pub source_port: u16,
  pub destination_address: Ipv4Addr,
  pub destination_port: u16,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Tcp6Addresses {
  pub source_address: Ipv6Addr,
  pub source_port: u16,
  pub destination_address: Ipv6Addr,
  pub destination_port: u16,
}

impl Tcp4Addresses {
  pub fn source(&self) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(self.source_address), self.source_port)
  }

  pub fn destination(&self) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(self.destination_address), self.destination_port)
  }
}

impl Tcp6Addresses {
  pub fn source(&self) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(self.source_address), self.source_port)
  } 
  
  pub fn destination(&self) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(self.destination_address), self.destination_port)
  }
}

  
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct UnixAddresses {
  pub source: [u8; 108],
  pub destination: [u8; 108],
}


// #[derive(Debug, thiserror::Error)]
// pub enum ParseError {
//   #[error("proxy protocol v1 not utf8")]
//   V1NotUtf8,
//   #[error("proxy protocol v1 parse error: {0}")]
//   V1Parse(ppp::v1::ParseError),
//   #[error("proxy protocol v2 parse error: {0}")]
//   V2Parse(ppp::v2::ParseError),
// }

// impl ParseError {
//   pub fn is_incomplete(&self) -> bool {
//     match self {
//       ParseError::V1NotUtf8 => false,
//       ParseError::V1Parse(e) => e.is_incomplete(),
//       ParseError::V2Parse(e) => e.is_incomplete(),
//     }
//   }
// }

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
  #[error("proxy protocol parse error: {0}")]
  Parse(#[from] proxy_header::Error),
  #[error("proxy protocol convert error: {0}")]
  FamilyMismatch(#[from] FamilyMismatch),
}

impl ParseError {
  pub fn is_incomplete(&self) -> bool {
    matches!(self, ParseError::Parse(proxy_header::Error::BufferTooShort))
  }
}

pub fn parse(buf: &[u8], expect: ExpectProxyProtocol) -> Result<ProxyHeader, ParseError> {

  let config = match expect {
    ExpectProxyProtocol::V1 => proxy_header::ParseConfig {
      allow_v1: true,
      allow_v2: false,
      include_tlvs: false,
    },
    ExpectProxyProtocol::V2 => proxy_header::ParseConfig {
      allow_v1: false,
      allow_v2: true,
      include_tlvs: false,
    },
    ExpectProxyProtocol::Any => proxy_header::ParseConfig {
      allow_v1: true,
      allow_v2: true,
      include_tlvs: false,
    },
  };

  let (aux, _) = proxy_header::ProxyHeader::parse(buf, config)?;
  let header = aux.try_into()?;

  Ok(header)
}

pub async fn read<S: AsyncRead + Unpin>(stream: &mut S, expect: ExpectProxyProtocol) -> Result<ProxyHeader, ProxyProtocolError> { 
  
  // 128 is a good upper guess for a proxy header buffer size, it will grow if needed
  let mut buf = Vec::with_capacity(128);
  loop {
    let byte = stream.read_u8().await?;
    buf.push(byte);

    match parse(&buf, expect) {
      Ok(header) => return Ok(header),
      Err(e) => {
        if e.is_incomplete() {
          continue;
        } else {
          return Err(e.into());
        }
      }
    }
  }
}

pub fn encode(header: &ProxyHeader, version: ProxyProtocolVersion) -> Result<Vec<u8>, ProxyProtocolError> {
  match version {
    ProxyProtocolVersion::V1 => {
      let target = match header {
        ProxyHeader::Unknown => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Local => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Unspecified => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Unix(_) => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Tcp4(a) => {
          proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress {
            protocol: proxy_header::Protocol::Stream,
            source: SocketAddr::new(IpAddr::V4(a.source_address), a.source_port),
            destination: SocketAddr::new(IpAddr::V4(a.destination_address), a.destination_port),
          })
        }
        ProxyHeader::Tcp6(a) => {
          proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress {
            protocol: proxy_header::Protocol::Stream,
            source: SocketAddr::new(IpAddr::V6(a.source_address), a.source_port),
            destination: SocketAddr::new(IpAddr::V6(a.destination_address), a.destination_port),
          })
        }
      };

      // 128 is a good upper guess for a proxy header buffer size, it will grow if needed
      let mut buf = Vec::with_capacity(107);

      target.encode_v1(&mut buf)
        .map_err(ProxyProtocolError::Encode)?;

      Ok(buf)
    }
    ProxyProtocolVersion::V2 => {
      let target = match header {
        ProxyHeader::Unknown => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Local => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Unspecified => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Unix(_) => proxy_header::ProxyHeader::with_local(),
        ProxyHeader::Tcp4(a) => proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress {
          protocol: proxy_header::Protocol::Stream,
          source: SocketAddr::new(IpAddr::V4(a.source_address), a.source_port),
          destination: SocketAddr::new(IpAddr::V4(a.destination_address), a.destination_port),
        }),
        ProxyHeader::Tcp6(a) => proxy_header::ProxyHeader::with_address(proxy_header::ProxiedAddress {
          protocol: proxy_header::Protocol::Stream,
          source: SocketAddr::new(IpAddr::V6(a.source_address), a.source_port),
          destination: SocketAddr::new(IpAddr::V6(a.destination_address), a.destination_port),
        }),
      };

      let mut buf = Vec::with_capacity(128);
      target.encode_v2(&mut buf)
        .map_err(ProxyProtocolError::Encode)?;

      Ok(buf)
    }
  }
}  


#[derive(Clone)]
pub struct ProxyProtocolConnector {
  inner: HttpConnector,
  config: Option<ProxyProtocolConfig>,
}

impl ProxyProtocolConnector {
  pub fn new(
    inner: HttpConnector,
    config: Option<ProxyProtocolConfig>
  ) -> Self {
    Self {
      inner,
      config,
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyProtocolConnectorError<E> {
  #[error("connect error: {0}")]
  Inner(#[source] E),
  #[error("proxy protocol encode error: {0}")]
  ProxyHeaderEncode(#[source] crate::proxy_protocol::ProxyProtocolError),
  #[error("proxy protocol write error: {0}")]
  ProxyHeaderWrite(#[source] std::io::Error),
  #[error("proxy protocol write timeout")]
  ProxyHeaderWriteTimeout,
}

impl Service<Uri> for ProxyProtocolConnector {
  type Error = ProxyProtocolConnectorError<<HttpConnector as Service<hyper::http::Uri>>::Error>;
  type Response = TokioIo<TcpStream>;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

  fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
      .map_err(ProxyProtocolConnectorError::Inner)
  }

  fn call(&mut self, uri: hyper::http::Uri) -> Self::Future {
    let mut this = self.clone();

    async move {
      
      let mut stream = this.inner.call(uri).await
        .map_err(ProxyProtocolConnectorError::Inner)?
        .into_inner();

      if let Some(config) = &this.config {
        let encoded = crate::proxy_protocol::encode(&config.header, config.version)
          .map_err(ProxyProtocolConnectorError::ProxyHeaderEncode)?;
      
        tokio_util::time::FutureExt::timeout(
          stream.write_all(&encoded),
          config.timeout
        )
        .await
        .map_err(|_| ProxyProtocolConnectorError::ProxyHeaderWriteTimeout)?
        .map_err(ProxyProtocolConnectorError::ProxyHeaderWrite)?;
      }
      
      Ok(TokioIo::new(stream))
    }.boxed()
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use std::io::Cursor;
  use tokio::io::AsyncReadExt;

  #[tokio::test]
  pub async fn read_v1_ipv4() {
    let buffer = String::from("PROXY TCP4 127.0.0.1 192.168.0.1 12345 443\r\n12345678");
    let target = ProxyHeader::Tcp4(Tcp4Addresses {
      source_address: Ipv4Addr::new(127, 0, 0, 1),
      source_port: 12345,
      destination_address: Ipv4Addr::new(192, 168, 0, 1),
      destination_port: 443,
    });
    
    let mut io = Cursor::new(buffer);
    let header = read(&mut io, ExpectProxyProtocol::V1)
      .await
      .unwrap();

    assert_eq!(header, target);
    
    let mut post = String::new();
    io.read_to_string(&mut post)
      .await
      .unwrap();

    assert_eq!(post, "12345678");
  }

  #[tokio::test]
  pub async fn read_v1_ipv6() {
    let buffer = String::from("PROXY TCP6 ::ffff ::ffff:ffff 12345 443\r\n12345678");
    let target = ProxyHeader::Tcp6(Tcp6Addresses {
      source_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xffff),
      source_port: 12345,
      destination_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xffff, 0xffff),
      destination_port: 443, 
    });

    let mut io = Cursor::new(buffer);
    let header = read(&mut io, ExpectProxyProtocol::V1)
      .await
      .unwrap();

    assert_eq!(header, target);
    
    let mut post = String::new();
    io.read_to_string(&mut post)
      .await
      .unwrap();

    assert_eq!(post, "12345678");
  }

  #[tokio::test]
  pub async fn read_v1_ipv4_expect_any() {
    let buffer = String::from("PROXY TCP4 127.0.0.1 192.168.0.1 12345 443\r\n12345678");
    let target = ProxyHeader::Tcp4(Tcp4Addresses {
      source_address: Ipv4Addr::new(127, 0, 0, 1),
      source_port: 12345,
      destination_address: Ipv4Addr::new(192, 168, 0, 1),
      destination_port: 443,
    });

    let mut io = Cursor::new(buffer);
    let header = read(&mut io, ExpectProxyProtocol::Any)
      .await
      .unwrap();

    assert_eq!(header, target);

    let mut post = String::new();
    io.read_to_string(&mut post)
      .await
      .unwrap();

    assert_eq!(post, "12345678");
  }

  #[tokio::test]
  pub async fn read_v1_ipv6_expect_any() {
    let buffer = String::from("PROXY TCP6 ::ffff ::ffff:ffff 12345 443\r\n12345678");
    let target = ProxyHeader::Tcp6(Tcp6Addresses {
      source_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xffff),
      source_port: 12345,
      destination_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xffff, 0xffff),
      destination_port: 443, 
    });

    let mut io = Cursor::new(buffer);
    let header = read(&mut io, ExpectProxyProtocol::Any)
      .await
      .unwrap();

    assert_eq!(header, target);

    let mut post = String::new();
    io.read_to_string(&mut post)
      .await
      .unwrap();

    assert_eq!(post, "12345678");
  }

  #[tokio::test]
  pub async fn v1_unknown() {
    let buffer = String::from("PROXY UNKNOWN\r\n12345678");
    let target = ProxyHeader::Unknown;
    let mut io = Cursor::new(buffer);
    let header = read(&mut io, ExpectProxyProtocol::V1)
      .await
      .unwrap();

    assert_eq!(header, target);
    assert!(header.source_addr().is_none());
    assert!(header.destination_addr().is_none());
    
    let mut post = String::new();
    io.read_to_string(&mut post)
      .await
      .unwrap();

    assert_eq!(post, "12345678");
  }

  #[tokio::test]
  pub async fn v1_unknown_expect_any() {
    let buffer = String::from("PROXY UNKNOWN\r\n12345678");
    let target = ProxyHeader::Unknown;
    let mut io = Cursor::new(buffer);
    let header = read(&mut io, ExpectProxyProtocol::Any)
      .await
      .unwrap();

    assert_eq!(header, target);
    assert!(header.source_addr().is_none());
    assert!(header.destination_addr().is_none());

    let mut post = String::new();
    io.read_to_string(&mut post)
      .await
      .unwrap();

    assert_eq!(post, "12345678");
  }


  #[test]
  pub fn encode_v1_ipv4() {
    let header = ProxyHeader::Tcp4(Tcp4Addresses {
      source_address: Ipv4Addr::new(127, 0, 0, 1),
      source_port: 12345,
      destination_address: Ipv4Addr::new(192, 168, 0, 1),
      destination_port: 443,
    });
    
    let buf = encode(&header, ProxyProtocolVersion::V1)
      .unwrap();

    assert_eq!(buf, b"PROXY TCP4 127.0.0.1 192.168.0.1 12345 443\r\n");
  }

  #[test]
  pub fn encode_v1_ipv6() {
    let header = ProxyHeader::Tcp6(Tcp6Addresses {
      source_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xffff),
      source_port: 12345,
      destination_address: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xffff, 0xffff),
      destination_port: 443,
    });

    let buf = encode(&header, ProxyProtocolVersion::V1)
      .unwrap();

    assert_eq!(buf, b"PROXY TCP6 ::ffff ::ffff:ffff 12345 443\r\n");
  }

  #[test]
  pub fn issue_repr() {
    use proxy_header::ProxyHeader;

    let bufs = [
      "PROXY UNK",
      "PROXY TCP4",
      "PROXY TCP6"
    ];
    let config = proxy_header::ParseConfig {
      allow_v1: true,
      allow_v2: true,
      include_tlvs: false,
    };

    for buf in bufs {
      let err = ProxyHeader::parse(buf.as_bytes(), config)
      .unwrap_err();

      // this fails with Error::Invalid instead of Error::BufferTooShort
      assert!(
        matches!(err, proxy_header::Error::BufferTooShort),
        "fail: {buf}"
      )
    }
  }
}
