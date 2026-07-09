use std::sync::Arc;
use rustls::{server::ResolvesServerCert, sign::CertifiedKey};

use crate::config::server_name::ServerName;

#[derive(Debug)]
pub struct CertResolver<T = Arc<CertifiedKey>>  {
  items: Vec<(ServerName, T)>,
}

impl<T> CertResolver<T> {
  pub fn new() -> Self {
    Self {
      items: Vec::new(),
    }
  }

  pub fn add(&mut self, server_name: ServerName, key: T) -> &mut Self {
    self.items.push((server_name, key));
    self
  }

  pub fn items(&self) -> &[(ServerName, T)] {
    &self.items
  }

  pub fn reset(&mut self) {
    self.items.clear();
  }

  pub fn resolve_for_server_name<'a, S: Into<Option<&'a str>>>(&self, server_name: S) -> Option<&T> {
    match server_name.into() {
      Some(wanted_name) => {
        for (pattern, key) in &self.items {
          if pattern.matches(wanted_name) {
            return Some(key)
          }
        }

        None
      }

      // without SNI only a catch-all entry (an app without server_names) can serve,
      // serving a name-specific certificate to a client that didn't ask for that name
      // would only fail validation at the client end
      None => {
        for (pattern, key) in &self.items {
          if matches!(pattern, ServerName::All) {
            return Some(key)
          }
        }

        None
      }
    }
  }
}

impl Default for CertResolver {
  fn default() -> Self {
    Self::new()
  }
}

impl ResolvesServerCert for CertResolver {
  fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
    self
      .resolve_for_server_name(client_hello.server_name())
      .cloned()
  }
}

#[cfg(test)]
mod test {
  use regex::Regex;

use crate::config::regex::SRegex;

use super::*;


  #[test]
  fn does_not_resolve_without_server_name() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");

    assert_eq!(resolver.resolve_for_server_name(None), None);
  }

  #[test]
  fn resolves_catch_all_without_server_name() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");
    resolver.add(ServerName::All, "all");

    assert_eq!(resolver.resolve_for_server_name(None), Some(&"all"));
    assert_eq!(resolver.resolve_for_server_name("bar.com"), Some(&"all"));
  }

  #[test]
  fn does_not_resolve_unmatched_server_name() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");

    assert_eq!(resolver.resolve_for_server_name("bar.com"), None);
  }

  #[test]
  fn reset() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");

    assert_eq!(resolver.resolve_for_server_name("foo.com"), Some(&"foo"));

    resolver.reset();

    assert_eq!(resolver.resolve_for_server_name("foo.com"), None);
  }

  #[test]
  fn resolves_server_name() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");
    resolver.add(ServerName::Exact(String::from("bar.com")), "bar");

    assert_eq!(resolver.resolve_for_server_name("foo.com"), Some(&"foo"));
    assert_eq!(resolver.resolve_for_server_name("bar.com"), Some(&"bar"));

    assert_eq!(resolver.resolve_for_server_name("baz.com"), None);
  }

  #[test]
  fn resolves_regex() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.add(ServerName::Regex{ regex: SRegex(Regex::new(r"^foo\.com$").unwrap() ) }, "foo");
    resolver.add(ServerName::Regex{ regex: SRegex(Regex::new(r"^bar\.com$").unwrap() ) }, "bar");
    resolver.add(ServerName::Exact(String::from("baz.com")), "baz");

    assert_eq!(resolver.resolve_for_server_name("foo.com"), Some(&"foo"));
    assert_eq!(resolver.resolve_for_server_name("bar.com"), Some(&"bar"));

    assert_eq!(resolver.resolve_for_server_name("baz.com"), Some(&"baz"));

    assert_eq!(resolver.resolve_for_server_name("qux.com"), None);
  }
}
