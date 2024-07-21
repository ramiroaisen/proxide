use hyper::header::HeaderValue;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SHeaderValue(#[serde(with = "super::header_value")] pub HeaderValue);

crate::newtype!(SHeaderValue => HeaderValue);
crate::json_schema_as!(SHeaderValue => String);

pub fn serialize<S>(value: &HeaderValue, ser: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  let helper = String::from_utf8_lossy(value.as_bytes());
  helper.serialize(ser)
}

pub fn deserialize<'de, D>(de: D) -> Result<HeaderValue, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let s: String = String::deserialize(de)?;
  HeaderValue::try_from(s)
    .map_err(|e| serde::de::Error::custom(format!("invalid header value: {e}")))
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn serialize() {
    let header_value = SHeaderValue(HeaderValue::from_static("header-value"));
    let actual = serde_json::to_string(&header_value).unwrap();
    assert_eq!(actual, "\"header-value\"");
  }

  #[test]
  fn deserialize() {
    let header_value = SHeaderValue(HeaderValue::from_static("header-value"));
    let actual = serde_json::from_str::<SHeaderValue>("\"header-value\"").unwrap();
    assert_eq!(actual, header_value);
  }
}
