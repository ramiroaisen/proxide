use std::{borrow::Cow, fmt::Display};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{json_schema_as, util::trim};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContentTypeMatcher {
  // matches a type with any subtype, eg: text/*
  Type(Cow<'static, str>),
  // matches a full type eg: application/json
  Full(Cow<'static, str>),
}

json_schema_as!(ContentTypeMatcher => String);

impl ContentTypeMatcher {
  /// This function will panic on invalid input
  pub const fn from_static(v: &'static str) -> Self {
    if const_str::ends_with!(v, "/*") {
      let str = const_str::unwrap!(const_str::strip_suffix!(v, "/*"));
      Self::Type(Cow::Borrowed(str))
    } else {
      Self::Full(Cow::Borrowed(v))
    }
  }

  pub fn matches(&self, content_type: &[u8]) -> bool {
    let content_type = trim(content_type);

    match self {
      Self::Type(self_ty) => match content_type.get(0..self_ty.len()) {
        None => false,
        Some(content_type_ty) => match content_type.get(self_ty.len()) {
          Some(b'/') => content_type_ty.eq_ignore_ascii_case(self_ty.as_bytes()),
          _ => false,
        },
      },

      Self::Full(full_ty) => match content_type.get(0..full_ty.len()) {
        None => false,
        Some(slice) => match content_type.get(full_ty.len()) {
          None | Some(b';') => slice.eq_ignore_ascii_case(full_ty.as_bytes()),
          _ => false,
        },
      },
    }
  }
}

impl<T: AsRef<str>> From<T> for ContentTypeMatcher {
  fn from(value: T) -> Self {
    let str = value.as_ref().trim();

    if str.ends_with("/*") {
      Self::Type(str[0..str.len() - 2].trim().to_string().into())
    } else {
      Self::Full(str.to_string().into())
    }
  }
}

impl Display for ContentTypeMatcher {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ContentTypeMatcher::Type(value) => write!(f, "{value}/*"),
      ContentTypeMatcher::Full(value) => write!(f, "{}", value),
    }
  }
}

impl Serialize for ContentTypeMatcher {
  fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
    self.to_string().serialize(ser)
  }
}

impl<'de> Deserialize<'de> for ContentTypeMatcher {
  fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
    let s = String::deserialize(de)?;
    Ok(ContentTypeMatcher::from(s))
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn str_roundtrip() {
    let cases = [
      ("text/plain", "text/plain"),
      (" application/json", "application/json"),
      ("text/html ", "text/html"),
      (" text/html ", "text/html"),
      ("text/*", "text/*"),
      ("text/* ", "text/*"),
      (" text/*", "text/*"),
      (" text/* ", "text/*"),
    ];

    for (source, expected) in cases {
      let matcher = ContentTypeMatcher::from(source);
      let actual = matcher.to_string();
      assert_eq!(actual, expected);
    }
  }

  #[test]
  fn serde_roundtrip() {
    let cases = [
      ("text/plain", "text/plain"),
      (" application/json", "application/json"),
      ("text/html ", "text/html"),
      (" text/html ", "text/html"),
      ("text/*", "text/*"),
      ("text/* ", "text/*"),
      (" text/*", "text/*"),
      (" text/* ", "text/*"),
    ];

    for (source, expected) in cases {
      let json = serde_json::to_string(source).unwrap();
      let matcher = serde_json::from_str::<ContentTypeMatcher>(&json).unwrap();
      let actual = serde_json::to_string(&matcher).unwrap();
      assert_eq!(actual, format!("\"{expected}\""));
    }
  }

  #[test]
  fn parse() {
    use super::ContentTypeMatcher as C;
    let cases = [
      ("text/*", C::Type("text".into())),
      (" application/* ", C::Type("application".into())),
      ("image/* ", C::Type("image".into())),
      (" video/* ", C::Type("video".into())),
      ("text/html ", C::Full("text/html".into())),
      (" application/json ", C::Full("application/json".into())),
      ("image/png ", C::Full("image/png".into())),
      (" video/mp4 ", C::Full("video/mp4".into())),
    ];

    for (source, expected) in cases {
      let matcher = ContentTypeMatcher::from(source);
      assert_eq!(matcher, expected);
    }
  }

  #[test]
  fn matches() {
    let cases = [
      // matcher: needle, content_type header: haystack, bool: expected
      ("text/html", "text/html", true),
      ("text/html", "text/plain", false),
      ("text/html", "text/plain; charset=asd", false),
      ("text/html", "text/html;charset=utf-8", true),
      ("text/*", "text/html  ", true),
      ("text/*", "text/plain;charset=utf-8", true),
      ("text/*", "application/json", false),
      ("text/*", "application/json;charset=utf-8", false),
    ];

    for (matcher, content_type, expected) in cases {
      let matcher = ContentTypeMatcher::from(matcher);
      let actual = matcher.matches(content_type.as_bytes());
      assert_eq!(
        actual, expected,
        "matcher: {matcher}, content_type: {content_type}"
      );
    }
  }

  #[test]
  fn from_static() {
    let cases = [
      ("text/plain", ContentTypeMatcher::Full("text/plain".into())),
      (
        "application/json",
        ContentTypeMatcher::Full("application/json".into()),
      ),
      ("text/*", ContentTypeMatcher::Type("text".into())),
    ];

    for (source, expected) in cases {
      let matcher = ContentTypeMatcher::from_static(source);
      assert_eq!(matcher, expected);
    }
  }
}
