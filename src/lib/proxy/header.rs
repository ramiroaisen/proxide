#![allow(clippy::declare_interior_mutable_const)]
use http::header::{Entry, IntoHeaderName};
use hyper::{
  header::{HeaderName, HeaderValue, VARY},
  HeaderMap,
};

use crate::util::trim;

pub const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
pub const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
pub const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
pub const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
pub const X_FORWARDED_PORT: HeaderName = HeaderName::from_static("x-forwarded-port");

pub const SERVER_HEADER_VALUE: HeaderValue = HeaderValue::from_static("proxide");
pub const CONNECTION_UPGRADE: HeaderValue = HeaderValue::from_static("upgrade");
pub const TEXT_PLAIN: HeaderValue = HeaderValue::from_static("text/plain;charset=utf-8");

pub const HTTPS: HeaderValue = HeaderValue::from_static("https");
pub const HTTP: HeaderValue = HeaderValue::from_static("http");

/// add a Vary to the current Vary header list
pub fn add_vary(headers: &mut HeaderMap, vary: HeaderValue) -> bool {
  map_list_add(headers, VARY, vary)
}

/// add a list item to a HeaderMap\[K\] value that is a comma separated list
/// or create the entry if it does not exist
pub fn map_list_add<K: IntoHeaderName>(
  headers: &mut HeaderMap,
  key: K,
  value: HeaderValue,
) -> bool {
  match headers.entry(key) {
    Entry::Occupied(mut entry) => list_add(entry.get_mut(), &value),

    Entry::Vacant(entry) => {
      entry.insert(value);
      true
    }
  }
}

/// split a header value by comma, trim and return an iterator
pub fn list(header: &[u8]) -> impl Iterator<Item = &[u8]> {
  header
    .split(|c| *c == b',')
    .map(trim)
    .filter(|str| !str.is_empty())
}

/// search a header value a in comma separated list, case insenstive
pub fn list_contains(header: &[u8], value: &[u8]) -> bool {
  list(header).any(|v| v.eq_ignore_ascii_case(value))
}

/// add an item to a header value that is a comma separated list
// we use HeaderValue here to ensure that the new HeaderValue is valid
pub fn list_add(existent: &mut HeaderValue, new_item: &HeaderValue) -> bool {
  let mut modify = false;
  let mut new_list: Vec<&[u8]> = list(existent.as_bytes()).collect::<Vec<&[u8]>>();
  for item in list(new_item.as_bytes()) {
    if !new_list
      .iter()
      .any(|existent_item| existent_item.eq_ignore_ascii_case(item))
    {
      modify = true;
      new_list.push(item);
    }
  }

  if !modify {
    return false;
  }

  let mut new_len = 0;
  for item in new_list.iter() {
    new_len += item.len() + 1;
  }
  new_len -= 1;

  let mut target = Vec::with_capacity(new_len);
  for (i, item) in new_list.iter().enumerate() {
    if i != 0 {
      target.push(b',');
    }
    target.extend_from_slice(item);
  }

  *existent = HeaderValue::from_bytes(&target).unwrap();

  true
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn list() {
    let cases: &[(&str, &[&str])] = &[
      ("h1", &["h1"]),
      ("h1,h2", &["h1", "h2"]),
      ("h1, ,  ,,h2", &["h1", "h2"]),
      ("h1,h2,, , ,h3", &["h1", "h2", "h3"]),
    ];

    for (header, expected) in cases {
      let actual = super::list(header.as_bytes()).collect::<Vec<_>>();
      let expected = expected
        .iter()
        .map(|item| item.as_bytes())
        .collect::<Vec<_>>();
      assert_eq!(actual, expected);
    }
  }

  #[test]
  fn contains() {
    let cases = &[
      ("h1", "h1", true),
      ("h1", "h2", false),
      ("h1,h2", "h1", true),
      ("h1,h2", "h2", true),
      ("h1,h2", "h3", false),
      ("h1,,h2", "h1", true),
      ("h1,,h2", "h2", true),
      ("h1,,h2", "h3", false),
      ("h1,,h2", "h4", false),
    ];

    for (haystack, needle, expected) in cases {
      assert_eq!(
        super::list_contains(haystack.as_bytes(), needle.as_bytes()),
        *expected
      );
    }
  }

  #[test]
  fn list_add() {
    let cases = &[
      ("h1", "h1", "h1"),
      ("h1", "h2", "h1,h2"),
      ("h1,h2", "h3", "h1,h2,h3"),
      ("h1, h2", "h3", "h1,h2,h3"),
      ("h1,h2", "h1", "h1,h2"),
      ("h1,h2", "h2", "h1,h2"),
      ("h1,h2", "h1,h2", "h1,h2"),
      ("h1, h2", "h1,h3", "h1,h2,h3"),
    ];

    for (list, item, expected) in cases {
      let mut list = HeaderValue::from_static(list);
      super::list_add(&mut list, &HeaderValue::from_static(item));
      assert_eq!(list.to_str().unwrap(), *expected);
    }
  }

  #[test]
  fn map_list_add() {
    {
      let mut headers = HeaderMap::new();
      let k = HeaderName::from_static("k");
      let v = HeaderValue::from_static("v");
      super::map_list_add(&mut headers, k.clone(), v.clone());
    }

    {
      let mut headers = HeaderMap::new();
      let k = HeaderName::from_static("k");
      let v = HeaderValue::from_static("v");
      headers.append(k.clone(), v.clone());
      let headers_clone = headers.clone();
      super::map_list_add(&mut headers, k.clone(), v.clone());
      assert_eq!(headers, headers_clone)
    }
  }
}
