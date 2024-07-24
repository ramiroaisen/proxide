use super::regex::SRegex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ServerName {
  // skip deserializing this variant, this will be used when no server names are specified
  #[serde(skip_deserializing)]
  All,
  Regex {
    regex: SRegex,
  },
  Exact(String),
}

impl ServerName {
  pub fn matches(&self, name: &str) -> bool {
    match self {
      ServerName::All => true,
      ServerName::Regex { regex } => regex.is_match(name),
      ServerName::Exact(exact) => exact.eq_ignore_ascii_case(name),
    }
  }
}

impl Display for ServerName {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ServerName::All => write!(f, "<all>"),
      ServerName::Exact(exact) => write!(f, "{}", exact),
      ServerName::Regex { regex } => write!(f, "{}", regex),
    }
  }
}

#[cfg(test)]
mod test {
  use regex::Regex;

  use super::*;

  #[test]
  fn display() {
    assert_eq!(ServerName::Exact("foo".to_string()).to_string(), "foo");
    assert_eq!(
      ServerName::Regex {
        regex: SRegex(Regex::new("^foo$").unwrap())
      }
      .to_string(),
      "regex:^foo$"
    );
  }
}
