use hyper::header::HeaderName;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SHeaderName(#[serde(with = "super::header_name")] pub HeaderName);
crate::newtype!(SHeaderName => HeaderName);
crate::json_schema_as!(SHeaderName => String);

pub fn serialize<S>(value: &HeaderName, ser: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  let str = value.as_str();
  str.serialize(ser)
}

pub fn deserialize<'de, D>(de: D) -> Result<HeaderName, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let s: String = String::deserialize(de)?;
  HeaderName::try_from(s).map_err(|e| serde::de::Error::custom(format!("invalid header name: {e}")))
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn serialize() {
    let header_name = SHeaderName(HeaderName::from_static("header-name"));
    let actual = serde_json::to_string(&header_name).unwrap();
    assert_eq!(actual, r#""header-name""#);
  }

  #[test]
  fn deserialize() {
    let header_name = SHeaderName(HeaderName::from_static("header-name"));
    let actual = serde_json::from_str::<SHeaderName>(r#""header-name""#).unwrap();
    assert_eq!(actual, header_name);
  }
}
