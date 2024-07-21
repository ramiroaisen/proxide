use rustls_pki_types::ServerName;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sni(pub ServerName<'static>);
crate::newtype!(Sni => ServerName<'static>);
crate::json_schema_as!(Sni => String);

impl Serialize for Sni {
  fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
    self.0.to_str().serialize(ser)
  }
}

impl<'de> serde::Deserialize<'de> for Sni {
  fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
    let s = String::deserialize(de)?;
    ServerName::try_from(s)
      .map_err(|e| serde::de::Error::custom(format!("invalid server name: {e}")))
      .map(Sni)
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use rustls_pki_types::IpAddr;

  #[test]
  fn serialize_dns_name() {
    let sni = Sni(ServerName::try_from("example.com").unwrap());
    let actual = serde_json::to_string(&sni).unwrap();
    assert_eq!(actual, "\"example.com\"");
  }

  #[test]
  fn serialize_ipv4() {
    let sni = Sni(ServerName::IpAddress(
      IpAddr::try_from("127.0.0.1").unwrap(),
    ));
    let actual = serde_json::to_string(&sni).unwrap();
    assert_eq!(actual, "\"127.0.0.1\"");
  }

  #[test]
  fn serialize_ipv6() {
    let sni = Sni(ServerName::IpAddress(IpAddr::try_from("::ffff").unwrap()));
    let actual = serde_json::to_string(&sni).unwrap();
    assert_eq!(actual, "\"::ffff\"");
  }

  #[test]
  fn deserialize() {
    let sni = Sni(ServerName::try_from("sni").unwrap());
    let actual = serde_json::from_str::<Sni>("\"sni\"").unwrap();
    assert_eq!(actual, sni);
  }

  #[test]
  fn deserialize_dns_name() {
    let sni = Sni(ServerName::try_from("example.com").unwrap());
    let actual = serde_json::from_str::<Sni>("\"example.com\"").unwrap();
    assert_eq!(actual, sni);
  }

  #[test]
  fn deserialize_ipv4() {
    let sni = Sni(ServerName::IpAddress(
      IpAddr::try_from("127.0.0.1").unwrap(),
    ));
    let actual = serde_json::from_str::<Sni>("\"127.0.0.1\"").unwrap();
    assert_eq!(actual, sni);
  }

  #[test]
  fn deserialize_ipv6() {
    let sni = Sni(ServerName::IpAddress(IpAddr::try_from("::ffff").unwrap()));
    let actual = serde_json::from_str::<Sni>("\"::ffff\"").unwrap();
    assert_eq!(actual, sni);
  }
}
