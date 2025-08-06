use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, str::FromStr};

use crate::proxy_protocol::ExpectProxyProtocol;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Listen {
  pub addr: PortOrAddr,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub ssl: Option<Ssl>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expect_proxy_protocol: Option<ExpectProxyProtocol>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ssl {
  pub cert: String,
  pub key: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub h3: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PortOrAddr {
  Port(u16),
  Addr(SocketAddr),
}

impl FromStr for PortOrAddr {
  type Err = std::num::ParseIntError;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    if let Ok(port) = s.parse::<SocketAddr>() {
      Ok(Self::Addr(port))
    } else {
      Ok(Self::Port(s.parse()?))
    }
  }
}

impl From<SocketAddr> for PortOrAddr {
  fn from(addr: SocketAddr) -> Self {
    Self::Addr(addr)
  }
}

impl From<u16> for PortOrAddr {
  fn from(port: u16) -> Self {
    Self::Port(port)
  }
}

impl PortOrAddr {
  pub fn addrs(self) -> Vec<SocketAddr> {
    match self {
      PortOrAddr::Port(port) => vec![
        SocketAddr::from(([0, 0, 0, 0], port)),
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
      ],

      PortOrAddr::Addr(addr) => vec![addr],
    }
  }

  pub fn matches_addr(self, addr: SocketAddr) -> bool {
    match self {
      PortOrAddr::Port(port) => addr.port() == port,
      PortOrAddr::Addr(self_addr) => {
        // different port or family (not match)
        if (self_addr.is_ipv4(), self_addr.port()) != (addr.is_ipv4(), addr.port()) {
          false
        // unspecified matches all ips
        } else if self_addr.ip().is_unspecified() {
          true
        // ips are the same
        } else {
          self_addr.ip() == addr.ip()
        }
      }
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn deserialize() {
    // all convinations
    let cases = [
      (
        r#"{
          "addr": "0.0.0.0:8080"
        }"#,
        Listen {
          addr: "0.0.0.0:8080".parse::<SocketAddr>().unwrap().into(),
          ssl: None,
          expect_proxy_protocol: None,
        },
      ),
      (
        r#"{
          "addr": "[::ffff]:8080"
        }"#,
        Listen {
          addr: "[::ffff]:8080".parse::<SocketAddr>().unwrap().into(),
          ssl: None,
          expect_proxy_protocol: None,
        },
      ),
      (
        r#"{
          "addr": 443
        }"#,
        Listen {
          addr: PortOrAddr::Port(443),
          ssl: None,
          expect_proxy_protocol: None,
        },
      ),
      (
        r#"{
          "addr": "127.0.0.1:8080",
          "ssl": {
            "cert": "cert/self-signed-cert.pem",
            "key": "cert/self-signed-key.pem"
          }
        }"#,
        Listen {
          addr: "127.0.0.1:8080".parse().unwrap(),
          ssl: Some(Ssl {
            cert: "cert/self-signed-cert.pem".to_string(),
            key: "cert/self-signed-key.pem".to_string(),
            h3: None,
          }),
          expect_proxy_protocol: None,
        },
      ),
      (
        r#"{
          "addr": "127.0.0.1:8080",
          "ssl": {
            "cert": "cert/self-signed-cert.pem",
            "key": "cert/self-signed-key.pem"
          },
          "expect_proxy_protocol": "v1"
        }"#,
        Listen {
          addr: "127.0.0.1:8080".parse().unwrap(),
          ssl: Some(Ssl {
            cert: "cert/self-signed-cert.pem".to_string(),
            key: "cert/self-signed-key.pem".to_string(),
            h3: None,
          }),
          expect_proxy_protocol: Some(ExpectProxyProtocol::V1),
        },
      ),
    ];

    for (source, expected) in cases {
      let actual = serde_json::from_str::<Listen>(source).unwrap();
      assert_eq!(actual, expected);
    }
  }
}
