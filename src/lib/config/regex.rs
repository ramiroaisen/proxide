use std::{fmt::Display, ops::{Deref, DerefMut}};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct SRegex(pub Regex);

impl Eq for SRegex {}

impl PartialEq for SRegex {
  fn eq(&self, other: &Self) -> bool {
    self.0.as_str() == other.0.as_str()
  }
}

impl Display for SRegex {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "regex:{}", self.0.as_str())
  }
}

impl std::hash::Hash for SRegex {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.0.as_str().hash(state);
  }
}

impl Deref for SRegex {
  type Target = Regex;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl DerefMut for SRegex {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}

impl JsonSchema for SRegex {
  fn schema_name() -> String {
    "Regex".into()
  }

  fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
    String::json_schema(gen)
  }
}

impl<'de> Deserialize<'de> for SRegex {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    Ok(SRegex(Regex::new(&s).map_err(serde::de::Error::custom)?))
  }
}

impl Serialize for SRegex {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(self.0.as_str())
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn regex_serde() {
    let regex = SRegex(Regex::new(r"^/foo$").unwrap());
    let expected = r#""^/foo$""#;
    assert_eq!(serde_json::to_string(&regex).unwrap(), expected);
  }

  #[test]
  fn serde_roundtrip() {
    let regex = SRegex(Regex::new(r"^/foo$").unwrap());
    let expected = r#""^/foo$""#;
    assert_eq!(serde_json::to_string(&regex).unwrap(), expected);
    assert_eq!(serde_json::from_str::<SRegex>(expected).unwrap(), regex);
  }

  #[test]
  fn eq_true() {
    let regex1 = SRegex(Regex::new(r"^/foo$").unwrap());
    let regex2 = SRegex(Regex::new(r"^/foo$").unwrap());
    assert_eq!(regex1, regex2);
  }

  #[test]
  fn eq_false() {
    let regex1 = SRegex(Regex::new(r"^/foo$").unwrap());
    let regex2 = SRegex(Regex::new(r"^/bar$").unwrap());
    assert_ne!(regex1, regex2);
  }
}