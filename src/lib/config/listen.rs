use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::proxy_protocol::ExpectProxyProtocol;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Listen {
  pub addr: SocketAddr,
  pub ssl: Option<Ssl>,
  pub expect_proxy_protocol: Option<ExpectProxyProtocol>,
}

crate::json_schema_as!(Listen => ListenHelper);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListenHelper {
  pub addr: PortOrAddr,
  pub ssl: Option<Ssl>,
  pub expect_proxy_protocol: Option<ExpectProxyProtocol>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ssl {
  pub cert: String,
  pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PortOrAddr {
  Port(u16),
  Addr(SocketAddr),
}

pub fn deserialize_listen_vec<'de, D>(deserializer: D) -> Result<Vec<Listen>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let helper = Vec::<ListenHelper>::deserialize(deserializer)?;
  let mut target: Vec<Listen> = vec![];

  for item in helper {
    match &item.addr {
      PortOrAddr::Addr(addr) => {
        target.push(Listen {
          addr: *addr,
          ssl: item.ssl,
          expect_proxy_protocol: item.expect_proxy_protocol,
        });
      }

      PortOrAddr::Port(port) => {
        let v4 = SocketAddr::from(([0, 0, 0, 0], *port));
        let v6 = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], *port));
        target.push(Listen {
          addr: v4,
          ssl: item.ssl.clone(),
          expect_proxy_protocol: item.expect_proxy_protocol,
        });
        target.push(Listen {
          addr: v6,
          ssl: item.ssl,
          expect_proxy_protocol: item.expect_proxy_protocol,
        });
      }
    }
  }

  Ok(target)
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
          addr: "0.0.0.0:8080".parse().unwrap(),
          ssl: None,
          expect_proxy_protocol: None,
        },
      ),
      (
        r#"{
          "addr": "[::ffff]:8080"
        }"#,
        Listen {
          addr: "[::ffff]:8080".parse().unwrap(),
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
