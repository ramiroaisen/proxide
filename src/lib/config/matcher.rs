use std::net::SocketAddr;
use std::net::IpAddr;
use http::header::AUTHORIZATION;
use http::Method;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::proxy::header::list_contains;

use super::regex::SRegex;

#[derive(Debug, Clone, Copy)]
pub struct RequestInfo<'a, B> {
  pub request: &'a hyper::Request<B>,
  pub remote_addr: SocketAddr,
}


/// Match requests by many parameters. \
/// To use in `$config.http.apps[n].when[n].match`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestMatcher {
  /// matches all requests
  All,  
  /// matches requests by path, see [`PathMatcher`]
  Path(PathMatcher),
  /// matches requests by header, see [`HeaderMatcher`]
  Header(HeaderMatcher),
  /// matches requests by method, see [`MethodMatcher`]
  Method(MethodMatcher),
  /// matches requests by client ip, see [`IpMatcher`]
  Ip(IpMatcher),
  /// matches requests by basic auth, see [`BasicAuthMatcher`]
  BasicAuth(BasicAuthMatcher),
  /// matches requests that do not match the specified matcher
  Not(Box<RequestMatcher>),
  /// matches requests that match any of the specified matchers
  Or(Vec<RequestMatcher>),
  /// matches requests that match all of the specified matchers
  And(Vec<RequestMatcher>),
}

/// Match requests by path
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathMatcher {
  /// matches all paths
  All,
  /// matches exactly the path specified 
  Exact(String),
  /// matches paths that start with the specified prefix optionally followed by a slash
  Scope(String),
  /// matches paths that match the specified regex
  Regex(SRegex),
}

/// Match requests by header
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HeaderMatcher {
  /// matches if the header is present in the request
  Exists(String),
  /// matches if the header with specified name is equal to the specified value
  Exact(String, String),
  /// matches if the header with specified name is a list of comma separated values that contains the specified value
  ListContains(String, String),
  /// matches if the header with specified name matches the specified regex
  Regex(String, SRegex)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MethodMatcher {
  /// matches if the method is equal to the specified method
  Eq(String),
  /// matches if the method is not equal to the specified method
  Ne(String),
  /// matches the specified method
  In(Vec<String>),
  /// matches if the method is not in the specified list
  NotIn(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpMatcher {
  /// matches if the ip is equal to the specified ip
  Eq(IpAddr),
  /// matches if the ip is not equal to the specified ip
  Ne(IpAddr),
  /// matches the specified ip
  In(Vec<IpAddr>),
  /// matches if the ip is not in the specified list
  NotIn(Vec<IpAddr>),
  /// matches if the ip is between the specified range
  Range(IpAddr, IpAddr),
}


impl RequestMatcher {
  pub fn matches<B>(&self, target: &RequestInfo<'_, B>) -> bool { 
    match self {
      RequestMatcher::All => true,
      RequestMatcher::Path(matcher) => matcher.matches(target.request.uri().path()),
      RequestMatcher::Header(matcher) => matcher.matches(target.request.headers()),
      RequestMatcher::Method(matcher) => matcher.matches(target.request.method()),
      RequestMatcher::Ip(matcher) => matcher.matches(target.remote_addr.ip()),
      RequestMatcher::BasicAuth(matcher) => matcher.matches(target.request.headers()),
      RequestMatcher::Not(matcher) => !matcher.matches(target),
      RequestMatcher::Or(matchers) => {
        matchers.iter().any(|matcher| matcher.matches(target))
      }
      RequestMatcher::And(matchers) => {
        matchers.iter().all(|matcher| matcher.matches(target))
      }
    }
  }
}

impl PathMatcher {
  pub fn matches(&self, path: &str) -> bool { 
    match self {
      PathMatcher::All => true,
      PathMatcher::Exact(exact) => path == exact,
      PathMatcher::Scope(scope) => {
        if path == scope {
          true
        } else if !scope.ends_with('/')  {
          if path.starts_with(scope) {
            path.as_bytes().get(scope.len()) == Some(&b'/')
          } else {
            false
          }
        } else {
          false
        }
      }

      PathMatcher::Regex(regex) => regex.is_match(path),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BasicAuthMatcher {
  pub user: String,
  pub password: String,
}

impl BasicAuthMatcher {
  pub fn matches(&self, headers: &hyper::HeaderMap) -> bool {
    let header = match headers.get(AUTHORIZATION) {
      None => return false,
      Some(header) => header,
    };

    let auth = match header.to_str() {
      Ok(auth) => auth,
      Err(_) => return false,
    };
    // this match is case insensitive
    const BASIC: &str = "basic ";
    
    match auth.get(0..BASIC.len()) {
      None => return false,
      Some(leading) => {
        if !leading.eq_ignore_ascii_case(BASIC) {
          return false;
        }
      }
    }

    let encoded = match auth.get(BASIC.len()..) {
      Some(encoded) => encoded,
      None => return false,
    };

    let decoded_vec = {
      use base64::prelude::{Engine, BASE64_STANDARD};
      match BASE64_STANDARD.decode(encoded) {
        Ok(decoded) => decoded,
        Err(_) => return false,
      }
    };

    let decoded = match String::from_utf8(decoded_vec) {
      Ok(decoded) => decoded,
      Err(_) => return false,
    };
    
    let sep_index = match decoded.find(':') {
      Some(sep_index) => sep_index,
      None => return false,
    };

    let user = match decoded.get(..sep_index) {
      Some(user) => user,
      None => return false,
    };

    let password = match decoded.get((sep_index + 1)..) {
      Some(password) => password,
      None => return false,
    };

    user == self.user && password == self.password
  }
}


impl HeaderMatcher {
  pub fn matches(&self, headers: &hyper::HeaderMap) -> bool {
    match self {
      HeaderMatcher::Exists(name) => headers.contains_key(name),
      HeaderMatcher::Exact(name, value) => {
        match headers.get(name) {
          None => false,
          Some(header) => header == value,
        }
      }
      HeaderMatcher::ListContains(name, value) => {
        match headers.get(name) {
          None => false,
          Some(header) => list_contains(header.as_bytes(), value.as_bytes()),
        }
      }
      HeaderMatcher::Regex(name, regex) => {
        match headers.get(name) {
          None => false,
          Some(header) => match header.to_str() {
            Err(_) => false,
            Ok(value) => regex.is_match(value),
          }
        }
      }
    }
  }
}

impl MethodMatcher {
  pub fn matches(&self, method: &Method) -> bool {
    match self {
      MethodMatcher::Ne(m) => !m.eq_ignore_ascii_case(method.as_str()),
      MethodMatcher::Eq(m) => m.eq_ignore_ascii_case(method.as_str()),
      MethodMatcher::In(methods) => {
        methods.iter().any(|m| m.eq_ignore_ascii_case(method.as_str()))
      }
      MethodMatcher::NotIn(methods) => {
        methods.iter().all(|m| !m.eq_ignore_ascii_case(method.as_str()))
      }
    }
  }
}

impl IpMatcher {
  pub fn matches(&self, ip: IpAddr) -> bool {
    match self {
      IpMatcher::Eq(inner) => *inner == ip,
      IpMatcher::Ne(inner) => *inner != ip,
      IpMatcher::In(ips) => ips.iter().any(|item| *item == ip),
      IpMatcher::NotIn(ips) => ips.iter().all(|item| *item != ip),
      IpMatcher::Range(from, to) => ip >= *from && ip <= *to,
    }
  }
}

#[cfg(test)]
mod test {

  mod not {
    use super::super::*;

    #[test] 
    fn all() {
      let matcher = RequestMatcher::All;
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      assert!(matcher.matches(&target));
    }

    #[test]
    fn match_not() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      let matcher = RequestMatcher::Not(Box::new(RequestMatcher::All));
      assert!(!matcher.matches(&target));

      let matcher = RequestMatcher::Not(Box::new(RequestMatcher::Not(Box::new(RequestMatcher::All))));
      assert!(matcher.matches(&target));
    }
  }

  mod or {
    use super::super::*;

    #[test]
    fn match_empty_is_false() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      let matcher = RequestMatcher::Or(vec![]);
      assert!(!matcher.matches(&target));
    }

    #[test]
    fn match_with_one_item() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      let matcher = RequestMatcher::Or(vec![RequestMatcher::All]);
      assert!(matcher.matches(&target));
      
      let matcher = RequestMatcher::Or(vec![RequestMatcher::Not(Box::new(RequestMatcher::All))]);      
      assert!(!matcher.matches(&target));
    }

    #[test]
    fn match_and() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };

      let matcher = RequestMatcher::Or(vec![
        RequestMatcher::All,
        RequestMatcher::All,
      ]);
      assert!(matcher.matches(&target));


      let matcher = RequestMatcher::Or(vec![
        RequestMatcher::All,
        RequestMatcher::Not(Box::new(RequestMatcher::All)),
      ]);
      assert!(matcher.matches(&target));

      let matcher = RequestMatcher::Or(vec![
        RequestMatcher::Not(Box::new(RequestMatcher::All)),
        RequestMatcher::Not(Box::new(RequestMatcher::All)),
      ]);
      assert!(!matcher.matches(&target));
    }
  }


  mod and {
    use super::super::*;

    #[test]
    fn match_empty_is_true() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      let matcher = RequestMatcher::And(vec![]);
      assert!(matcher.matches(&target));
    }

    #[test]
    fn match_with_one_item() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      let matcher = RequestMatcher::And(vec![RequestMatcher::All]);
      assert!(matcher.matches(&target));
      
      let matcher = RequestMatcher::And(vec![RequestMatcher::Not(Box::new(RequestMatcher::All))]);      
      assert!(!matcher.matches(&target));
    }

    #[test]
    fn match_and() {
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };

      let matcher = RequestMatcher::And(vec![
        RequestMatcher::All,
        RequestMatcher::All,
      ]);
      assert!(matcher.matches(&target));


      let matcher = RequestMatcher::And(vec![
        RequestMatcher::All,
        RequestMatcher::Not(Box::new(RequestMatcher::All)),
      ]);
      assert!(!matcher.matches(&target));

      let matcher = RequestMatcher::And(vec![
        RequestMatcher::Not(Box::new(RequestMatcher::All)),
        RequestMatcher::All,
      ]);
      assert!(!matcher.matches(&target));
    }
  }

  mod method {
    use super::super::*;

    #[test]
    fn match_eq() {
      let matcher = MethodMatcher::Eq("GET".into());
      assert!(matcher.matches(&Method::GET));
      assert!(!matcher.matches(&Method::POST));
    }

    #[test]
    fn match_ne() {
      let matcher = MethodMatcher::Ne("GET".into());
      assert!(!matcher.matches(&Method::GET));
      assert!(matcher.matches(&Method::POST));
    }

    #[test]
    fn match_in() {
      let matcher = MethodMatcher::In(vec!["GET".into(), "POST".into()]);
      assert!(matcher.matches(&Method::GET));
      assert!(matcher.matches(&Method::POST));
      assert!(!matcher.matches(&Method::PUT));
    }

    #[test]
    fn match_nin() {
      let matcher = MethodMatcher::NotIn(vec!["GET".into(), "POST".into()]);
      assert!(!matcher.matches(&Method::GET));
      assert!(!matcher.matches(&Method::POST));
      assert!(matcher.matches(&Method::PUT));
    }
  }

  mod path {
    use regex::Regex;

    use super::super::*;

    #[test]
    fn match_all() {
      let matcher = PathMatcher::All;
      assert!(matcher.matches("/"));
      assert!(matcher.matches("/foo"));
      assert!(matcher.matches("/foo/bar"));
    }

    #[test]
    fn match_exact() {
      let matcher = PathMatcher::Exact("/foo".into());
      assert!(matcher.matches("/foo"));
      assert!(!matcher.matches("/foo/bar"));
      assert!(!matcher.matches("/"));
    }

    #[test]
    fn match_scope() {
      let matcher = PathMatcher::Scope("/foo".into());
      assert!(matcher.matches("/foo"));
      assert!(matcher.matches("/foo/bar"));
      assert!(!matcher.matches("/"));
    }

    #[test]
    fn match_regex() {
      let matcher = PathMatcher::Regex(SRegex(Regex::new(r"^/foo$").unwrap()));
      assert!(matcher.matches("/foo"));
      assert!(!matcher.matches("/foo/"));
      assert!(!matcher.matches("/foo/bar"));
      assert!(!matcher.matches("/"));
    }
  }

  mod header {
    use regex::Regex;

    use super::super::*;

    #[test]
    fn match_exists() {
      let matcher = HeaderMatcher::Exists("x-real-ip".into());
      let mut headers = hyper::HeaderMap::new();
      headers.insert("x-real-ip", "127.0.0.1".parse().unwrap());
      assert!(matcher.matches(&headers));
      
      let empty = hyper::HeaderMap::new();
      assert!(!matcher.matches(&empty))
    }

    #[test]
    fn match_equals() {
      let matcher = HeaderMatcher::Exact("x-real-ip".into(), "127.0.0.1".into());
      let mut headers = hyper::HeaderMap::new();
      headers.insert("x-real-ip", "127.0.0.1".parse().unwrap());
      assert!(matcher.matches(&headers));
      
      let matcher = HeaderMatcher::Exact("x-real-ip".into(), "127.0.0.2".into());
      assert!(!matcher.matches(&headers))
    }

    #[test]
    fn match_regex() {
      let matcher = HeaderMatcher::Regex("x-real-ip".into(), SRegex(Regex::new(r"^127\.0\.0\.1$").unwrap()));
      let mut headers = hyper::HeaderMap::new();
      headers.insert("x-real-ip", "127.0.0.1".parse().unwrap());
      assert!(matcher.matches(&headers));
      
      let empty = hyper::HeaderMap::new();
      let matcher = HeaderMatcher::Regex("x-real-ip".into(), SRegex(Regex::new("^$").unwrap()));
      assert!(!matcher.matches(&empty))
    }

    #[test]
    fn match_list_contains() {
      let matcher = HeaderMatcher::ListContains("header".into(), "value2".into());
      let mut headers = hyper::HeaderMap::new();
      headers.insert("header", "value1, value2, value3".parse().unwrap()); 
      assert!(matcher.matches(&headers));
      
      let matcher = HeaderMatcher::ListContains("header".into(), "value5".into());
      assert!(!matcher.matches(&headers))
    }
  }


  mod ip {
    use super::super::*;

    #[test]
    fn match_eq() {
      // ip4
      let matcher = IpMatcher::Eq(IpAddr::from([127, 0, 0, 1]));
      assert!(matcher.matches(IpAddr::from([127, 0, 0, 1])));
      assert!(!matcher.matches(IpAddr::from([127, 0, 0, 2])));
      
      // ip6
      let matcher = IpMatcher::Eq(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]));
      assert!(matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
      assert!(!matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 2])));
    }

    #[test]
    fn match_ne() {
      // ip4
      let matcher = IpMatcher::Ne(IpAddr::from([127, 0, 0, 1]));
      assert!(!matcher.matches(IpAddr::from([127, 0, 0, 1])));
      assert!(matcher.matches(IpAddr::from([127, 0, 0, 2])));
      
      // ip6
      let matcher = IpMatcher::Ne(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]));
      assert!(!matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
      assert!(matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 2])));
    }

    #[test]
    fn match_in() {
      // ip4
      let matcher = IpMatcher::In(vec![IpAddr::from([127, 0, 0, 1])]);
      assert!(matcher.matches(IpAddr::from([127, 0, 0, 1])));
      assert!(!matcher.matches(IpAddr::from([127, 0, 0, 2])));
      
      // ip6
      let matcher = IpMatcher::In(vec![IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])]);
      assert!(matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
      assert!(!matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 2])));
    }

    #[test]
    fn match_nin() {
      // ip4
      let matcher = IpMatcher::NotIn(vec![IpAddr::from([127, 0, 0, 1])]);
      assert!(!matcher.matches(IpAddr::from([127, 0, 0, 1])));
      assert!(matcher.matches(IpAddr::from([127, 0, 0, 2])));
      
      // ip6
      let matcher = IpMatcher::NotIn(vec![IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])]);
      assert!(!matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
      assert!(matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 2])));
    }

    #[test]
    fn match_range() {
      // ip4
      let matcher = IpMatcher::Range(IpAddr::from([127, 0, 0, 1]), IpAddr::from([127, 0, 0, 2]));
      assert!(matcher.matches(IpAddr::from([127, 0, 0, 1])));
      assert!(matcher.matches(IpAddr::from([127, 0, 0, 2])));
      assert!(!matcher.matches(IpAddr::from([127, 0, 0, 3])));
    
      // ip6
      let matcher = IpMatcher::Range(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]), IpAddr::from([0, 0, 0, 0, 0, 0, 0, 2]));
      assert!(matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])));
      assert!(matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 2])));
      assert!(!matcher.matches(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 3])));
    }
  }

  mod basic_auth {
    use super::super::*;

    #[test]
    fn not_match_empty() {
      let matcher = RequestMatcher::BasicAuth(BasicAuthMatcher {
        user: "user".to_owned(),
        password: "password".to_owned(),
      });
      let request = hyper::Request::builder().body(()).unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      assert!(!matcher.matches(&target));
    }

    #[test]
    fn not_match_with_other_values() {
      let matcher = RequestMatcher::BasicAuth(BasicAuthMatcher {
        user: "user".to_owned(),
        password: "password".to_owned(),
      });
      let request = hyper::Request::builder()
        .header(AUTHORIZATION, "Basic dXNlcjp")
        .body(())
        .unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      assert!(!matcher.matches(&target));
    }

    #[test]
    fn match_basic_auth_with_spaces() {
      let matcher = RequestMatcher::BasicAuth(BasicAuthMatcher {
        user: "user".to_owned(),
        password: "password".to_owned(),
      });
      let request = hyper::Request::builder()
        .header(AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA==")
        .body(())
        .unwrap();
      let target = RequestInfo {
        request: &request,
        remote_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
      };
      assert!(matcher.matches(&target));
    }
  }
}