use hyper::header::{HeaderValue, CONNECTION, UPGRADE};
use hyper::Method;
use crate::proxy::header::list_contains;

// this will matched in case insensitive form
const UPGRADE_STR: &[u8] = b"upgrade";

/// Whether the request is an HTTP Upgrade
/// this will only be Some() for GET requests that have the
/// "upgrade" value in the list under the Connection header
/// and have a value present in the Upgrade header. \
/// the returned HeaderValue is the one under the Upgrade key
pub fn request_connection_upgrade<'a>(
  method: &Method,
  headers: &'a hyper::HeaderMap,
) -> Option<&'a HeaderValue> {
  
  if method == Method::GET {
    let connection = headers.get(CONNECTION)?.as_bytes();
    // this is case insensitive
    if list_contains(connection, UPGRADE_STR) {
      headers.get(UPGRADE)
    } else {
      None
    }
  } else {
    None  
  }
}

/// Whether the response is an HTTP Upgrade. \
/// The returned HeaderValue is the one under the Upgrade
/// key or None if the response is not an upgrade
pub fn response_connection_upgrade(headers: &hyper::HeaderMap) -> Option<&HeaderValue> {
  let connection = headers.get(CONNECTION)?;
  if list_contains(connection.as_bytes(), UPGRADE_STR) {
    headers.get(UPGRADE)
  } else {
    None
  }
}

/// Whether the response is http/1.1 and does not have `connection: close`. \
/// If no `Connection` header is present and the request is http/1.1, this will return true (as of http/1.1 default)
pub fn response_is_keep_alive(version: hyper::Version, headers: &hyper::HeaderMap) -> bool {

  match version {
    hyper::Version::HTTP_11 => {
      let connection = match headers.get(CONNECTION) {
        // the lack of Connection header indicates Keep-Alive in http/1.1
        None => return true,
        Some(connection) => connection,
      };
    
      // return true if the connection does not contain close
      // instead of checking for keep-alive, as keep-alive is the http/1.1 default
      !list_contains(connection.as_bytes(), b"close") 
    }

    _ => false,
  }
}

#[cfg(test)]
mod test {
  use crate::proxy::header::CONNECTION_UPGRADE;
  use super::*;

  #[test]
  fn request_connection_upgrade_non_method() {
    let methods = [
      Method::HEAD,
      Method::OPTIONS,
      Method::TRACE,
      Method::CONNECT,
      Method::PATCH,
      Method::DELETE,
    ];

    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, CONNECTION_UPGRADE);
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));

    for method in methods {
      let r = super::request_connection_upgrade(&method, &headers);
      assert!(r.is_none());
    }
  }

  #[test]
  fn get_upgrade() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, CONNECTION_UPGRADE);
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    let r = super::request_connection_upgrade(&Method::GET, &headers).unwrap();
    assert_eq!(r, "websocket");
  }

  #[test]
  fn get_non_upgrade() {
    let headers = hyper::HeaderMap::new();
    let r = super::request_connection_upgrade(&Method::GET, &headers);
    assert!(r.is_none());
  }

  #[test]
  fn http10_non_keep_alive() {
    let version = hyper::Version::HTTP_10;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    assert!(!super::response_is_keep_alive(version, &headers))
  }

  #[test]
  fn http11_keep_alive() {
    let version = hyper::Version::HTTP_11;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    assert!(super::response_is_keep_alive(version, &headers));
  }

  #[test]
  fn http11_keep_alive_mixed() {
    let version = hyper::Version::HTTP_11;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive,upgrade"));
    assert!(super::response_is_keep_alive(version, &headers));    
  }

  #[test]
  fn http11_non_keep_alive_other_non_close() {
    let version = hyper::Version::HTTP_11;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("hello"));
    assert!(super::response_is_keep_alive(version, &headers));
  }

  #[test]
  fn http11_non_keep_alive_close() {
    let version = hyper::Version::HTTP_11;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    assert!(!super::response_is_keep_alive(version, &headers));
  }

  #[test]
  fn http11_non_keep_alive_close_mixed() {
    let version = hyper::Version::HTTP_11;
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("close,upgrade"));
    assert!(!super::response_is_keep_alive(version, &headers));
  }

  #[test]
  fn http11_keep_alive_none() {
    let version = hyper::Version::HTTP_11;
    let headers = hyper::HeaderMap::new();
    assert!(super::response_is_keep_alive(version, &headers));
  }

  #[test]
  fn response_connection_upgrade_true() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, CONNECTION_UPGRADE);
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    let r = super::response_connection_upgrade(&headers).unwrap();
    assert_eq!(r, "websocket");
  }

  #[test]
  fn response_connection_upgrade_false() {
    let mut headers = hyper::HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    let r = super::response_connection_upgrade(&headers);
    assert!(r.is_none());
  }
}
