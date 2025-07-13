use http::HeaderValue;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::{Display, Write};
use std::iter::Iterator;
use std::str::FromStr;
use std::{convert::Infallible, net::SocketAddr};

use crate::context::{Interpolation, Variable};
use crate::interpolate::{render, tokens, Token};
use crate::json_schema_as;
use crate::proxy::service::HttpConnectionKind;
use crate::proxy_protocol::ProxyHeader;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpInterpolation {
  Empty,
  Literal(String),
  Interpolated(Vec<Token<HttpVar, String>>),
}
json_schema_as!(HttpInterpolation => String);

impl HttpInterpolation {
  pub fn is_empty(&self) -> bool {
    matches!(self, HttpInterpolation::Empty)
  }
}

#[allow(clippy::needless_lifetimes)]
impl<'var, 'context> Interpolation<'var, 'context> for HttpInterpolation {
  type Var = HttpVar;
  type Context = HttpContext<'context>;
  fn render(&self, f: &mut String, ctx: &Self::Context) -> Result<(), Infallible> {
    use HttpInterpolation as I;
    match self {
      I::Empty => {}
      I::Literal(lit) => f.push_str(lit),
      I::Interpolated(tokens) => render(f, tokens, ctx)?,
    }

    Ok(())
  }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid http interpolation: {0}")]
pub enum InvalidHttpInterpolation {
  InvalidExpression(#[from] InvalidExpressionError),
}

impl FromStr for HttpInterpolation {
  type Err = InvalidHttpInterpolation;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let mut tokens = tokens::<HttpVar>(s);
    let mut collected = Vec::<Token<HttpVar, String>>::new();
    while let Some(token) = tokens.next().transpose()? {
      match token {
        Token::Lit(lit) => collected.push(Token::Lit(lit.to_string())),
        Token::Var(var) => collected.push(Token::Var(var)),
      }
    }

    let simple = match collected.len() {
      0 => HttpInterpolation::Empty,
      1 => match collected.first().unwrap() {
        Token::Lit(lit) => {
          if lit.is_empty() {
            HttpInterpolation::Empty
          } else {
            HttpInterpolation::Literal(lit.to_string())
          }
        }
        Token::Var(_) => HttpInterpolation::Interpolated(collected),
      },
      _ => HttpInterpolation::Interpolated(collected),
    };

    Ok(simple)
  }
}

impl Display for HttpInterpolation {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      HttpInterpolation::Empty => "".fmt(f)?,
      HttpInterpolation::Literal(lit) => lit.fmt(f)?,
      HttpInterpolation::Interpolated(tokens) => {
        let mut buf = String::new();
        for token in tokens {
          match token {
            Token::Lit(lit) => buf.push_str(lit),
            Token::Var(var) => write!(buf, "${{{}}}", var.as_str()).unwrap(),
          }
        }
        buf.fmt(f)?
      }
    }

    Ok(())
  }
}

impl Serialize for HttpInterpolation {
  fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
    self.to_string().serialize(s)
  }
}

impl<'de> Deserialize<'de> for HttpInterpolation {
  fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
    let s = String::deserialize(d)?;
    HttpInterpolation::from_str(&s).map_err(serde::de::Error::custom)
  }
}

pub struct HttpContext<'a> {
  pub connection_kind: HttpConnectionKind,
  pub host: &'a str,
  pub port: Option<u16>,
  pub method: &'a hyper::Method,
  pub version: hyper::Version,
  pub uri: &'a hyper::Uri,
  pub remote_addr: SocketAddr,
  pub local_addr: SocketAddr,
  pub proxy_header: Option<&'a ProxyHeader>,
  pub request_forwarded: Option<&'a HeaderValue>,
  pub request_x_forwarded_for: Option<&'a HeaderValue>,
  pub request_x_forwarded_host: Option<&'a HeaderValue>,
  pub request_x_forwarded_proto: Option<&'a HeaderValue>,
  pub request_x_forwarded_port: Option<&'a HeaderValue>,
}

macro_rules! var {
  ($f:ident, $ctx:ident, scheme) => {{
    $f.push_str(match $ctx.connection_kind {
      HttpConnectionKind::Http => "http",
      HttpConnectionKind::Https => "https",
      #[cfg(feature = "h3")]
      HttpConnectionKind::H3 => "https",
    })
  }};

  ($f:ident, $ctx:ident, proto) => {{
    $f.push_str(match $ctx.connection_kind {
      HttpConnectionKind::Http => "http",
      HttpConnectionKind::Https => "https",
      #[cfg(feature = "h3")]
      HttpConnectionKind::H3 => "https",
    })
  }};

  ($f:ident, $ctx:ident, host) => {{
    $f.push_str($ctx.host);
  }};

  ($f:ident, $ctx:ident, port) => {{
    if let Some(port) = $ctx.port {
      let _ = write!($f, ":{}", port);
    }
  }};

  ($f:ident, $ctx:ident, method) => {{
    $f.push_str($ctx.method.as_str())
  }};

  ($f:ident, $ctx:ident, version) => {{
    $f.push_str(match $ctx.version {
      hyper::Version::HTTP_09 => "0.9",
      hyper::Version::HTTP_10 => "1.0",
      hyper::Version::HTTP_11 => "1.1",
      hyper::Version::HTTP_2 => "2.0",
      hyper::Version::HTTP_3 => "3.0",
      _ => "unknown",
    })
  }};

  ($f:ident, $ctx:ident, request_uri) => {{
    match $ctx.uri.path_and_query() {
      Some(uri) => $f.push_str(uri.as_str()),
      None => $f.push_str("/"),
    }
  }};

  ($f:ident, $ctx:ident, connection_remote_ip) => {{
    let _ = write!($f, "{}", $ctx.remote_addr.ip());
  }};

  ($f:ident, $ctx:ident, proxy_protocol_remote_ip) => {{
    match $ctx.proxy_header {
      Some(header) => match header.source_addr() {
        Some(addr) => {
          let _ = write!($f, "{}", addr.ip());
        }
        None => {
          $f.push_str("unknown");
        }
      },

      None => {
        $f.push_str("unknown");
      }
    }
  }};

  ($f:ident, $ctx:ident, remote_ip) => {{
    match &$ctx.proxy_header {
      Some(header) => match header.source_addr() {
        Some(addr) => {
          let _ = write!($f, "{}", addr.ip());
        }
        None => {
          let _ = write!($f, "{}", $ctx.remote_addr.ip());
        }
      },

      None => {
        let _ = write!($f, "{}", $ctx.remote_addr.ip());
      }
    }
  }};

  ($f:ident, $ctx:ident, forwarded) => {{
    // for(self)
    if $ctx.remote_addr.is_ipv4() {
      let _ = write!($f, "for={}", $ctx.remote_addr);
    } else {
      let _ = write!(
        $f,
        "for=\"[{}]:{}\"",
        $ctx.remote_addr.ip(),
        $ctx.remote_addr.port()
      );
    }

    // by(self)
    if $ctx.local_addr.is_ipv4() {
      let _ = write!($f, ";by={}", $ctx.local_addr);
    } else {
      let _ = write!(
        $f,
        ";by=\"[{}]:{}\"",
        $ctx.local_addr.ip(),
        $ctx.local_addr.port()
      );
    }

    // proto(self)
    $f.push_str(";proto=");
    $f.push_str(match $ctx.connection_kind {
      HttpConnectionKind::Http => "http",
      HttpConnectionKind::Https => "https",
      #[cfg(feature = "h3")]
      HttpConnectionKind::H3 => "https",
    });

    $f.push_str(";host=");
    $f.push_str($ctx.host);

    // by(proxy_protocol)
    if let Some(header) = &$ctx.proxy_header {
      match (header.destination_addr(), header.source_addr()) {
        (Some(addr), source_addr) => {
          if addr.is_ipv4() {
            let _ = write!($f, ",for={}", addr);
          } else {
            let _ = write!($f, ",for=\"[{}]:{}\"", addr.ip(), addr.port());
          }

          if let Some(source_addr) = source_addr {
            if source_addr.is_ipv4() {
              let _ = write!($f, ";by={}", source_addr);
            } else {
              let _ = write!($f, ";by=\"[{}]:{}\"", source_addr.ip(), source_addr.port());
            }
          }
        }
        (None, Some(source_addr)) => {
          if source_addr.is_ipv4() {
            let _ = write!($f, ";by={}", source_addr);
          } else {
            let _ = write!($f, ";by=\"[{}]:{}\"", source_addr.ip(), source_addr.port());
          }
        }
        (None, None) => {}
      }
    }

    // headers
    if let Some(prev) = $ctx.request_forwarded {
      if let Ok(prev) = prev.to_str() {
        $f.push(',');
        $f.push_str(prev);
      }
    }
  }};

  ($f:ident, $ctx:ident, x_forwarded_for) => {{
    // we do not include the port here as some server implementations
    // are not able to handle this header correctly when it includes a port
    // the above, x-forwarded-port
    // Eg: 255.1.5.9
    // Eg: 255.1.5.9,::ffff:ffff

    // self
    let _ = write!($f, "{}", $ctx.remote_addr.ip());
    if let Some(proxy_header) = &$ctx.proxy_header {
      if let Some(addr) = proxy_header.source_addr() {
        let _ = write!($f, ",{}", addr.ip());
      }
    }

    // follow
    match &$ctx.request_x_forwarded_for {
      Some(header) => match header.to_str() {
        Ok(header) => {
          let _ = write!($f, ",{}", header);
        }
        _ => {}
      },
      _ => {}
    }
  }};

  ($f:ident, $ctx:ident, x_forwarded_port) => {{
    // Eg: 80
    // Eg: 80,443

    // self
    let _ = write!($f, "{}", $ctx.remote_addr.port());

    // proxy protocol
    if let Some(proxy_header) = &$ctx.proxy_header {
      if let Some(addr) = proxy_header.source_addr() {
        let _ = write!($f, ",{}", addr.port());
      }
    }

    // header
    match &$ctx.request_x_forwarded_port {
      Some(header) => match header.to_str() {
        Ok(header) => {
          let _ = write!($f, ",{}", header);
        }
        _ => {}
      },
      _ => {}
    }
  }};

  ($f:ident, $ctx:ident, x_forwarded_host) => {{
    // Eg: foo.com
    // Eg: foo.com,bar.com

    // self
    let _ = $f.write_str($ctx.host);

    // header
    match &$ctx.request_x_forwarded_host {
      Some(header) => match header.to_str() {
        Ok(header) => {
          let _ = write!($f, ",{}", header);
        }
        _ => {}
      },
      _ => {}
    }
  }};

  ($f:ident, $ctx:ident, x_forwarded_proto) => {{
    // Eg: https
    // Eg: https,http

    // self
    $f.push_str(match $ctx.connection_kind {
      HttpConnectionKind::Http => "http",
      HttpConnectionKind::Https => "https",
      #[cfg(feature = "h3")]
      HttpConnectionKind::H3 => "https",
    });

    // header
    match &$ctx.request_x_forwarded_proto {
      Some(header) => match header.to_str() {
        Ok(header) => {
          let _ = write!($f, ",{}", header);
        }
        _ => {}
      },
      _ => {}
    }
  }};

  ($f:ident, $ctx:ident, via) => {{
    // Eg: HTTP/1.1 example.com
    // Eg: HTTP/2.0 example.com:8000

    $f.push_str(match $ctx.version {
      hyper::Version::HTTP_09 => "HTTP/0.9",
      hyper::Version::HTTP_10 => "HTTP/1.0",
      hyper::Version::HTTP_11 => "HTTP/1.1",
      hyper::Version::HTTP_2 => "HTTP/2.0",
      hyper::Version::HTTP_3 => "HTTP/3.0",
      _ => "UKNOWN",
    });

    $f.push(' ');

    var!($f, $ctx, host);
    var!($f, $ctx, port);
  }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVar {
  Scheme,
  Proto,
  Host,
  Port,
  RequestUri,
  Method,
  Version,
  ProxyProtocolRemoteIp,
  ConnectionRemoteIp,
  RemoteIp,
  Forwarded,
  Via,
  XForwardedFor,
  XForwardedHost,
  XForwardedProto,
  XForwardedPort,
}

impl HttpVar {
  pub fn as_str(&self) -> &'static str {
    match self {
      HttpVar::Scheme => "scheme",
      HttpVar::Proto => "proto",
      HttpVar::Host => "host",
      HttpVar::Port => "port",
      HttpVar::RequestUri => "request_uri",
      HttpVar::Method => "method",
      HttpVar::Version => "version",
      HttpVar::ProxyProtocolRemoteIp => "proxy_protocol_remote_ip",
      HttpVar::ConnectionRemoteIp => "connection_remote_ip",
      HttpVar::RemoteIp => "remote_ip",
      HttpVar::Forwarded => "forwarded",
      HttpVar::Via => "via",
      HttpVar::XForwardedFor => "x_forwarded_for",
      HttpVar::XForwardedHost => "x_forwarded_host",
      HttpVar::XForwardedProto => "x_forwarded_proto",
      HttpVar::XForwardedPort => "x_forwarded_port",
    }
  }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid interpolation expression: {0}")]
pub struct InvalidExpressionError(pub String);

impl<'a> Variable<'a> for HttpVar {
  type FromExprErr = InvalidExpressionError;
  fn from_expr(expr: &str) -> Result<Self, InvalidExpressionError> {
    use HttpVar as V;
    let var = match expr {
      "scheme" => V::Scheme,
      "proto" => V::Proto,
      "host" => V::Host,
      "port" => V::Port,
      "request_uri" => V::RequestUri,
      "method" => V::Method,
      "version" => V::Version,
      "proxy_protocol_remote_ip" => V::ProxyProtocolRemoteIp,
      "connection_remote_ip" => V::ConnectionRemoteIp,
      "remote_ip" => V::RemoteIp,
      "forwarded" => V::Forwarded,
      "via" => V::Via,
      "x_forwarded_for" => V::XForwardedFor,
      "x_forwarded_host" => V::XForwardedHost,
      "x_forwarded_proto" => V::XForwardedProto,
      "x_forwarded_port" => V::XForwardedPort,
      _ => return Err(InvalidExpressionError(expr.to_string())),
    };

    Ok(var)
  }

  type Context = HttpContext<'a>;
  type RenderErr = Infallible;
  fn render(&self, f: &mut String, ctx: &Self::Context) -> Result<(), Self::RenderErr> {
    use HttpVar as V;
    match self {
      V::Scheme => var!(f, ctx, scheme),
      V::Proto => var!(f, ctx, proto),
      V::Host => var!(f, ctx, host),
      V::Port => var!(f, ctx, port),
      V::RequestUri => var!(f, ctx, request_uri),
      V::Method => var!(f, ctx, method),
      V::Version => var!(f, ctx, version),
      V::ProxyProtocolRemoteIp => var!(f, ctx, proxy_protocol_remote_ip),
      V::ConnectionRemoteIp => var!(f, ctx, connection_remote_ip),
      V::RemoteIp => var!(f, ctx, remote_ip),
      V::Forwarded => var!(f, ctx, forwarded),
      V::Via => var!(f, ctx, via),
      V::XForwardedFor => var!(f, ctx, x_forwarded_for),
      V::XForwardedHost => var!(f, ctx, x_forwarded_host),
      V::XForwardedProto => var!(f, ctx, x_forwarded_proto),
      V::XForwardedPort => var!(f, ctx, x_forwarded_port),
    };

    Ok(())
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use http::HeaderValue;
  use hyper::{Method, Uri, Version};
  use std::net::{IpAddr, Ipv4Addr, SocketAddr};

  // Helper function to create a HeaderValue from a string
  fn hv(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
  }

  #[test]
  fn interpolation_from_str_empty() {
    let interpolation = HttpInterpolation::from_str("").unwrap();
    assert_eq!(interpolation, HttpInterpolation::Empty);
  }

  #[test]
  fn interpolation_from_str_literal() {
    let interpolation = HttpInterpolation::from_str("hello").unwrap();
    assert_eq!(
      interpolation,
      HttpInterpolation::Literal("hello".to_string())
    );
  }

  #[test]
  fn interpolation_from_str_var() {
    let interpolation = HttpInterpolation::from_str("${host}").unwrap();
    assert_eq!(
      interpolation,
      HttpInterpolation::Interpolated(vec![Token::Var(HttpVar::Host)])
    );
  }

  #[test]
  fn interpolation_from_str_mixed() {
    let interpolation = HttpInterpolation::from_str("hello ${host}").unwrap();
    assert_eq!(
      interpolation,
      HttpInterpolation::Interpolated(vec![
        Token::Lit("hello ".to_string()),
        Token::Var(HttpVar::Host)
      ])
    );
  }

  #[test]
  fn display_interpolation_lieral() {
    let interpolation = HttpInterpolation::Literal("hello".to_string());
    assert_eq!(interpolation.to_string(), "hello");
  }

  #[test]
  fn display_interpolation() {
    let interpolation = HttpInterpolation::Interpolated(vec![
      Token::Lit("hello ".to_string()),
      Token::Var(HttpVar::Host),
    ]);
    assert_eq!(interpolation.to_string(), "hello ${host}");
  }

  #[test]
  fn serialize_interpolation() {
    let interpolation = HttpInterpolation::Literal("hello".to_string());
    let serialized = serde_json::to_string(&interpolation).unwrap();
    assert_eq!(serialized, "\"hello\"");
  }

  #[test]
  fn deserialize_interpolation() {
    let json = "\"hello\"";
    let interpolation: HttpInterpolation = serde_json::from_str(json).unwrap();
    assert_eq!(
      interpolation,
      HttpInterpolation::Literal("hello".to_string())
    );
  }

  #[test]
  fn var_as_str() {
    assert_eq!(HttpVar::Scheme.as_str(), "scheme");
  }

  #[test]
  fn var_from_expression() {
    let var = HttpVar::from_expr("host").unwrap();
    assert_eq!(var, HttpVar::Host);
  }

  #[test]
  fn from_expr_invalid() {
    let var = HttpVar::from_expr("invalid");
    assert!(var.is_err());
  }

  #[test]
  fn render_scheme() {
    let context = HttpContext {
      connection_kind: HttpConnectionKind::Https,
      host: "example.com",
      port: None,
      method: &Method::GET,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: None,
      request_x_forwarded_for: None,
      request_x_forwarded_host: None,
      request_x_forwarded_proto: None,
      request_x_forwarded_port: None,
    };
    let mut output = String::new();
    HttpVar::Scheme.render(&mut output, &context).unwrap();
    assert_eq!(output, "https");
  }

  // More tests can be added here for other variants and contexts...

  #[test]
  fn render_host() {
    let context = HttpContext {
      connection_kind: HttpConnectionKind::Http,
      host: "example.com",
      port: None,
      method: &Method::GET,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: None,
      request_x_forwarded_for: None,
      request_x_forwarded_host: None,
      request_x_forwarded_proto: None,
      request_x_forwarded_port: None,
    };
    let mut output = String::new();
    HttpVar::Host.render(&mut output, &context).unwrap();
    assert_eq!(output, "example.com");
  }

  #[test]
  fn render_forwarded_for() {
    let request_forwarded = hv("by=proxy");
    let request_x_forwarded_for = hv("2.2.2.2,3.3.3.3");
    let request_x_forwarded_host = hv("example.com");
    let request_x_forwarded_proto = hv("https");
    let request_x_forwarded_port = hv("443");

    let context = HttpContext {
      connection_kind: HttpConnectionKind::H3,
      host: "example.com",
      port: None,
      method: &Method::GET,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: Some(&request_forwarded),
      request_x_forwarded_for: Some(&request_x_forwarded_for),
      request_x_forwarded_host: Some(&request_x_forwarded_host),
      request_x_forwarded_proto: Some(&request_x_forwarded_proto),
      request_x_forwarded_port: Some(&request_x_forwarded_port),
    };
    let mut output = String::new();
    HttpVar::XForwardedFor
      .render(&mut output, &context)
      .unwrap();
    assert_eq!(output, "1.1.1.1,2.2.2.2,3.3.3.3");
  }

  #[test]
  fn render_proto() {
    let context = HttpContext {
      connection_kind: HttpConnectionKind::Https,
      host: "example.com",
      port: None,
      method: &Method::GET,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: None,
      request_x_forwarded_for: None,
      request_x_forwarded_host: None,
      request_x_forwarded_proto: None,
      request_x_forwarded_port: None,
    };
    let mut output = String::new();
    HttpVar::Proto.render(&mut output, &context).unwrap();
    assert_eq!(output, "https");
  }

  #[test]
  fn render_request_uri() {
    let uri = Uri::from_static("/path?query=1");
    let context = HttpContext {
      connection_kind: HttpConnectionKind::H3,
      host: "example.com",
      port: Some(8080),
      method: &Method::POST,
      version: Version::HTTP_11,
      uri: &uri,
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: None,
      request_x_forwarded_for: None,
      request_x_forwarded_host: None,
      request_x_forwarded_proto: None,
      request_x_forwarded_port: None,
    };
    let mut output = String::new();
    HttpVar::RequestUri.render(&mut output, &context).unwrap();
    assert_eq!(output, "/path?query=1");
  }

  #[test]
  fn render_forwarded() {
    let context: HttpContext<'_> = HttpContext {
      connection_kind: HttpConnectionKind::Http,
      host: "example.com",
      port: Some(8080),
      method: &Method::POST,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: None,
      request_x_forwarded_for: None,
      request_x_forwarded_host: None,
      request_x_forwarded_proto: None,
      request_x_forwarded_port: None,
    };
    let mut output = String::new();
    HttpVar::Forwarded.render(&mut output, &context).unwrap();
    assert_eq!(
      output,
      "for=1.2.3.4:1234;by=4.3.2.1:4321;proto=http;host=example.com"
    );
  }

  #[test]
  fn invalid_expression() {
    let error = InvalidExpressionError("unknown".to_string());
    assert_eq!(
      error.to_string(),
      "invalid interpolation expression: unknown"
    );
  }

  #[cfg(test)]
  #[test]
  fn all_vars() {
    let request_forwarded = hv("for=2.2.2.2");
    let request_x_forwarded_for = hv("2.2.2.2,3.3.3.3");
    let request_x_forwarded_host = hv("forwarded.com");
    let request_x_forwarded_proto = hv("https");
    let request_x_forwarded_port = hv("443");

    let context = HttpContext {
      connection_kind: HttpConnectionKind::Https,
      host: "example.com",
      port: Some(8080),
      method: &Method::POST,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/path?query=1"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: Some(&request_forwarded),
      request_x_forwarded_for: Some(&request_x_forwarded_for),
      request_x_forwarded_host: Some(&request_x_forwarded_host),
      request_x_forwarded_proto: Some(&request_x_forwarded_proto),
      request_x_forwarded_port: Some(&request_x_forwarded_port),
    };

    let cases = vec![
      (HttpVar::Scheme, "https"),
      (HttpVar::Proto, "https"),
      (HttpVar::Host, "example.com"),
      (HttpVar::Port, ":8080"),
      (HttpVar::RequestUri, "/path?query=1"),
      (HttpVar::Method, "POST"),
      (HttpVar::Version, "1.1"),
      (HttpVar::ConnectionRemoteIp, "1.2.3.4"),
      (HttpVar::RemoteIp, "1.2.3.4"),
      (
        HttpVar::Forwarded,
        "for=1.2.3.4:1234;by=4.3.2.1:4321;proto=https;host=example.com,for=2.2.2.2",
      ),
      (HttpVar::XForwardedFor, "1.2.3.4,2.2.2.2,3.3.3.3"),
      (HttpVar::XForwardedHost, "example.com,forwarded.com"),
      (HttpVar::XForwardedProto, "https,https"),
      (HttpVar::XForwardedPort, "1234,443"),
      (HttpVar::Via, "HTTP/1.1 example.com:8080"),
    ];

    for (var, expected) in cases {
      let mut output = String::new();
      var.render(&mut output, &context).unwrap();
      assert_eq!(output, expected, "Failed on {:?}", var);
    }
  }

  #[test]
  fn mixed_interpolation() {
    let request_forwarded = hv("for=2.2.2.2");
    let request_x_forwarded_for = hv("2.2.2.2,3.3.3.3");
    let request_x_forwarded_host = hv("forwarded.com");
    let request_x_forwarded_proto = hv("https");
    let request_x_forwarded_port = hv("443");

    let ctx = HttpContext {
      connection_kind: HttpConnectionKind::Https,
      host: "example.com",
      port: Some(8080),
      method: &Method::POST,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/path?query=1"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: Some(&request_forwarded),
      request_x_forwarded_for: Some(&request_x_forwarded_for),
      request_x_forwarded_host: Some(&request_x_forwarded_host),
      request_x_forwarded_proto: Some(&request_x_forwarded_proto),
      request_x_forwarded_port: Some(&request_x_forwarded_port),
    };

    // cases interpolation string, expected result
    let cases = vec![
      ("", ""),
      ("hello", "hello"),
      ("${host}${port} hello", "example.com:8080 hello"),
      ("hello ${host}", "hello example.com"),
      ("hello ${host} world", "hello example.com world"),
      ("hello ${host} ${method}", "hello example.com POST"),
      (
        "hello ${host} ${method} world",
        "hello example.com POST world",
      ),
      (
        "via: ${via}",
        "via: HTTP/1.1 example.com:8080",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri}",
        "hello example.com POST 1.1 /path?query=1",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} world",
        "hello example.com POST 1.1 /path?query=1 world",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip}",
        "hello example.com POST 1.1 /path?query=1 1.2.3.4",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip} world",
        "hello example.com POST 1.1 /path?query=1 1.2.3.4 world",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip} ${forwarded}",
        "hello example.com POST 1.1 /path?query=1 1.2.3.4 for=1.2.3.4:1234;by=4.3.2.1:4321;proto=https;host=example.com,for=2.2.2.2",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip} ${forwarded} world",
        "hello example.com POST 1.1 /path?query=1 1.2.3.4 for=1.2.3.4:1234;by=4.3.2.1:4321;proto=https;host=example.com,for=2.2.2.2 world",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip} ${forwarded} ${via}",
        "hello example.com POST 1.1 /path?query=1 1.2.3.4 for=1.2.3.4:1234;by=4.3.2.1:4321;proto=https;host=example.com,for=2.2.2.2 HTTP/1.1 example.com:8080",
      ),
      (
        "${host} ${method} ${version} ${request_uri} ${remote_ip} ${forwarded} ${via}",
        "example.com POST 1.1 /path?query=1 1.2.3.4 for=1.2.3.4:1234;by=4.3.2.1:4321;proto=https;host=example.com,for=2.2.2.2 HTTP/1.1 example.com:8080",
      ),
    ];

    for (source, expected) in cases {
      let parsed = HttpInterpolation::from_str(source).unwrap();
      let mut f = String::new();
      parsed.render(&mut f, &ctx).unwrap();
      assert_eq!(f, expected, "sorce: {source}");
    }
  }

  #[test]
  fn render_to_string() {
    let cases = vec![
      ("hello ${host}", "hello example.com"),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip}",
        "hello example.com GET 1.1 /path 127.0.0.1",
      ),
      (
        "hello ${host} ${method} ${version} ${request_uri} ${remote_ip} world",
        "hello example.com GET 1.1 /path 127.0.0.1 world",
      ),
    ];

    let ctx = HttpContext {
      connection_kind: HttpConnectionKind::Http,
      host: "example.com",
      port: None,
      method: &Method::GET,
      version: Version::HTTP_11,
      uri: &Uri::from_static("/path"),
      remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234),
      local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)), 4321),
      proxy_header: None,
      request_forwarded: None,
      request_x_forwarded_for: None,
      request_x_forwarded_host: None,
      request_x_forwarded_proto: None,
      request_x_forwarded_port: None,
    };

    for (source, expected) in cases {
      let parsed = HttpInterpolation::from_str(source).unwrap();
      let actual = parsed.render_to_string(&ctx).unwrap();
      assert_eq!(actual, expected, "sorce: {source}");
    }
  }
}
