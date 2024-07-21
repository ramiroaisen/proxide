use std::sync::Arc;
use rustls::{server::ResolvesServerCert, sign::CertifiedKey};

use crate::config::server_name::ServerName;

#[derive(Debug)]
pub struct CertResolver<T = Arc<CertifiedKey>>  {
  default: Option<T>,
  items: Vec<(ServerName, T)>,
}

impl<T> CertResolver<T> {
  pub fn new() -> Self {
    Self {
      default: None,
      items: Vec::new(),
    }
  }

  pub fn with_default<D: Into<Option<T>>>(default: D) -> Self {
    Self {
      default: default.into(),
      items: Vec::new(),
    }
  }

  pub fn default(&self) -> Option<&T> {
    self.default.as_ref()
  }

  pub fn set_default<K: Into<Option<T>>>(&mut self, key: K) -> &mut Self {
    self.default = key.into();
    self
  }

  pub fn add(&mut self, server_name: ServerName, key: T) -> &mut Self {
    self.items.push((server_name, key));
    self
  }

  pub fn items(&self) -> &[(ServerName, T)] {
    &self.items
  }

  pub fn reset(&mut self) {
    self.default = None;
    self.items.clear();
  }

  pub fn resolve_for_server_name<'a, S: Into<Option<&'a str>>>(&self, server_name: S) -> Option<&T> {
    let wanted_name = match server_name.into() {
      Some(name) => name,
      None => return self.default.as_ref()
    };

    for (pattern, key) in &self.items {
      if pattern.matches(wanted_name) {
        return Some(key)
      }
    }

    self.default.as_ref()
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
  fn resolves_default() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.set_default("default");
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");
    
    assert_eq!(resolver.resolve_for_server_name(None), Some(&"default"));
    assert_eq!(resolver.resolve_for_server_name("var.com"), Some(&"default"));
    
    let resolver2 = CertResolver::<&'static str>::new();
    assert_eq!(resolver2.resolve_for_server_name(None), None);
    assert_eq!(resolver2.resolve_for_server_name("example.com"), None);

    let resolver3 = CertResolver::with_default("default");
    assert_eq!(resolver3.resolve_for_server_name(None), Some(&"default"));
  }

  #[test]
  fn reset() {
    let mut resolver = CertResolver::<&'static str>::new();
    resolver.set_default("default");
    resolver.add(ServerName::Exact(String::from("foo.com")), "foo");

    assert_eq!(resolver.resolve_for_server_name(None), Some(&"default"));

    resolver.reset();

    assert_eq!(resolver.resolve_for_server_name(None), None);
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