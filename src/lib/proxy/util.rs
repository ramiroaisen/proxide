use crate::proxy::header::KEEP_ALIVE;
use hyper::{
  header::{CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE},
  HeaderMap, Request, Uri, Version,
};

use super::error::ProxyHttpError;

pub fn remove_hop_headers(headers: &mut HeaderMap) {
  headers.remove(CONNECTION);
  headers.remove(KEEP_ALIVE);
  headers.remove(TE);
  headers.remove(PROXY_AUTHORIZATION);
  headers.remove(PROXY_AUTHENTICATE);
  // headers.remove("transfer-encoding");
}

pub fn header_host(headers: &HeaderMap) -> Result<(&str, Option<u16>), ProxyHttpError> {
  let header = match headers.get(HOST) {
    Some(header) => header,
    None => return Err(ProxyHttpError::NoHost),
  };

  let str = header.to_str().map_err(|_| ProxyHttpError::InvalidHost)?;

  let mut split = str.rsplitn(2, ':');
  let port = match split.next() {
    Some(port) => port,
    None => return Ok((str, None)),
  };

  let port = match port.parse::<u16>() {
    Ok(port) => port,
    Err(_) => return Ok((str, None)),
  };

  let host = match split.next() {
    Some(host) => host,
    None => return Err(ProxyHttpError::InvalidHost),
  };

  Ok((host, Some(port)))
}

pub fn uri_host(uri: &Uri) -> Result<(&str, Option<u16>), ProxyHttpError> {
  match (uri.host(), uri.port()) {
    (Some(host), Some(port)) => Ok((host, Some(port.as_u16()))),
    (Some(host), None) => Ok((host, None)),
    (None, _) => Err(ProxyHttpError::InvalidHost),
  }
}

pub fn resolve_host_port<B>(req: &Request<B>) -> Result<(&str, Option<u16>), ProxyHttpError> {
  match req.version() {
    Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => header_host(req.headers()),

    _ => match header_host(req.headers()) {
      Ok((host, port)) => Ok((host, port)),
      Err(e) => {
        if matches!(e, ProxyHttpError::NoHost) {
          uri_host(req.uri())
        } else {
          Err(e)
        }
      }
    },
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use http::HeaderValue;

  #[test]
  fn header_host_exists() {
    let cases = [
      ("example.com", ("example.com", None)),
      ("example.com:8080", ("example.com", Some(8080))),
    ];

    for (existing, expected) in cases {
      let mut map = HeaderMap::new();
      map.insert(HOST, HeaderValue::from_static(existing));
      let tuple = header_host(&map).unwrap();
      assert_eq!(tuple, expected);
    }
  }

  #[test]
  fn header_host_not_exists() {
    let map = HeaderMap::new();
    assert!(matches!(
      header_host(&map).unwrap_err(),
      ProxyHttpError::NoHost
    ));
  }

  #[test]
  fn uri_host_valid() {
    let cases = [
      ("http://example.com", ("example.com", None)),
      ("https://example.com", ("example.com", None)),
      ("http://example.com:8080", ("example.com", Some(8080))),
      ("https://example.com:8080", ("example.com", Some(8080))),
    ];

    for (existing, expected) in cases {
      let uri = Uri::from_static(existing);
      let tuple = uri_host(&uri).unwrap();
      assert_eq!(tuple, expected);
    }
  }

  #[test]
  fn uri_host_err() {
    assert!(matches!(
      uri_host(&Uri::from_static("/asd")).unwrap_err(),
      ProxyHttpError::InvalidHost
    ));
  }
}
