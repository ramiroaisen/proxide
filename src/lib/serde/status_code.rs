use hyper::StatusCode;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SStatusCode(#[serde(with = "super::status_code")] pub StatusCode);

crate::newtype!(SStatusCode => StatusCode);
crate::json_schema_as!(SStatusCode => u16);

pub fn serialize<S>(value: &StatusCode, ser: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  value.as_u16().serialize(ser)
}

pub fn deserialize<'de, D>(de: D) -> Result<StatusCode, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let s = u16::deserialize(de)?;
  StatusCode::from_u16(s).map_err(|e| serde::de::Error::custom(format!("invalid status code: {e}")))
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn serialize() {
    let status_code = SStatusCode(StatusCode::OK);
    let actual = serde_json::to_string(&status_code).unwrap();
    assert_eq!(actual, "200");
  }

  #[test]
  fn deserialize() {
    let status_code = SStatusCode(StatusCode::OK);
    let actual = serde_json::from_str::<SStatusCode>("200").unwrap();
    assert_eq!(actual, status_code);
  }
}
