#![allow(clippy::declare_interior_mutable_const)]

#[cfg(feature = "compression-br")]
use async_compression::tokio::bufread::BrotliEncoder;
#[cfg(feature = "compression-deflate")]
use async_compression::tokio::bufread::DeflateEncoder;
#[cfg(feature = "compression-gzip")]
use async_compression::tokio::bufread::GzipEncoder;
#[cfg(feature = "compression-zstd")]
use async_compression::tokio::bufread::ZstdEncoder;
use async_compression::Level;
use std::{
  fmt::Display,
  io,
  pin::Pin,
  task::{Context, Poll},
};

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::BodyExt;
use hyper::{
  body::{Frame, SizeHint},
  header::HeaderValue,
  HeaderMap, StatusCode,
};
use pin_project::pin_project;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncRead};

use crate::config::Compress;
use crate::proxy::error::ProxyHttpError;
use crate::util::trim;
use crate::{body::Body, serde::content_type::ContentTypeMatcher};

#[cfg(feature = "compression-br")]
const CONTENT_ENCODING_BR: HeaderValue = HeaderValue::from_static("br");
#[cfg(feature = "compression-zstd")]
const CONTENT_ENCODING_ZSTD: HeaderValue = HeaderValue::from_static("zstd");
#[cfg(feature = "compression-gzip")]
const CONTENT_ENCODING_GZIP: HeaderValue = HeaderValue::from_static("gzip");
#[cfg(feature = "compression-deflate")]
const CONTENT_ENCODING_DEFLATE: HeaderValue = HeaderValue::from_static("deflate");

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
  #[cfg(feature = "compression-br")]
  Br,
  #[cfg(feature = "compression-zstd")]
  Zstd,
  #[cfg(feature = "compression-gzip")]
  Gzip,
  #[cfg(feature = "compression-deflate")]
  Deflate,
}

impl Encoding {
  pub const fn as_str(self) -> &'static str {
    match self {
      #[cfg(feature = "compression-br")]
      Encoding::Br => "br",
      #[cfg(feature = "compression-zstd")]
      Encoding::Zstd => "zstd",
      #[cfg(feature = "compression-gzip")]
      Encoding::Gzip => "gzip",
      #[cfg(feature = "compression-deflate")]
      Encoding::Deflate => "deflate",
    }
  }

  pub const fn to_header_value(&self) -> HeaderValue {
    match self {
      #[cfg(feature = "compression-br")]
      Encoding::Br => CONTENT_ENCODING_BR,
      #[cfg(feature = "compression-zstd")]
      Encoding::Zstd => CONTENT_ENCODING_ZSTD,
      #[cfg(feature = "compression-gzip")]
      Encoding::Gzip => CONTENT_ENCODING_GZIP,
      #[cfg(feature = "compression-deflate")]
      Encoding::Deflate => CONTENT_ENCODING_DEFLATE,
    }
  }
}

impl Display for Encoding {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

#[allow(clippy::large_enum_variant)]
#[pin_project(project = EncoderProjection)]
pub enum Encoder<R: AsyncRead + Send + 'static> {
  #[cfg(feature = "compression-br")]
  Brotli(#[pin] BrotliEncoder<R>),
  #[cfg(feature = "compression-zstd")]
  Zstd(#[pin] ZstdEncoder<R>),
  #[cfg(feature = "compression-gzip")]
  Gzip(#[pin] GzipEncoder<R>),
  #[cfg(feature = "compression-deflate")]
  Deflate(#[pin] DeflateEncoder<R>),
}

impl<R: AsyncBufRead + Send> Encoder<R> {
  #[cfg(feature = "compression-br")]
  pub fn brotli(reader: R, level: Level) -> Self {
    let encoder = BrotliEncoder::with_quality(reader, level);
    Self::Brotli(encoder)
  }

  #[cfg(feature = "compression-zstd")]
  pub fn zstd(reader: R, level: Level) -> Self {
    let encoder = ZstdEncoder::with_quality(reader, level);
    Self::Zstd(encoder)
  }

  #[cfg(feature = "compression-gzip")]
  pub fn gzip(reader: R, level: Level) -> Self {
    let encoder = GzipEncoder::with_quality(reader, level);
    Self::Gzip(encoder)
  }

  #[cfg(feature = "compression-deflate")]
  pub fn deflate(reader: R, level: Level) -> Self {
    let encoder = DeflateEncoder::with_quality(reader, level);
    Self::Deflate(encoder)
  }
}

impl<R: AsyncBufRead + Send + Sync> AsyncRead for Encoder<R> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    match self.project() {
      #[cfg(feature = "compression-br")]
      EncoderProjection::Brotli(encoder) => encoder.poll_read(cx, buf),
      #[cfg(feature = "compression-zstd")]
      EncoderProjection::Zstd(encoder) => encoder.poll_read(cx, buf),
      #[cfg(feature = "compression-gzip")]
      EncoderProjection::Gzip(encoder) => encoder.poll_read(cx, buf),
      #[cfg(feature = "compression-deflate")]
      EncoderProjection::Deflate(encoder) => encoder.poll_read(cx, buf),
    }
  }
}

/**
 * select an encoding from a list of encodings based on the client's accept-encoding header
 * the preference order is the order of the encodings in the list
 * that means the preference is set first by the server and then by the client
 **/
pub fn select_encoding(
  encodings: &[Compress],
  accept_encoding: Option<&HeaderValue>,
) -> Option<Compress> {
  accept_encoding?
    .as_bytes()
    .split(|&c| c == b',')
    .map(trim)
    .filter_map(|enc| {
      encodings
        .iter()
        .enumerate()
        .find(|(_, &e)| enc == e.algo.as_str().as_bytes())
    })
    .reduce(|(ai, a), (bi, b)| if ai <= bi { (ai, a) } else { (bi, b) })
    .map(|(_, enc)| enc)
    .copied()
}

pub fn should_compress(
  server_encodings: &[Compress],
  content_type_matchers: &[ContentTypeMatcher],
  min_size: u64,
  request_accept_encoding: Option<&HeaderValue>,
  upstream_status: StatusCode,
  upstream_body_size_hint: SizeHint,
  upstream_headers: &hyper::HeaderMap,
) -> Option<Compress> {
  if server_encodings.is_empty() {
    return None;
  }

  // only compress OK responses
  if upstream_status != StatusCode::OK {
    log::debug!("status is not OK");
    return None;
  }

  // only compress responses bigger than min_size
  if let Some(upper) = upstream_body_size_hint.upper() {
    if upper < min_size {
      log::debug!("upper limit under min_size: {} < {}", upper, min_size);
      return None;
    }
  }

  if let Some(content_encoding) = upstream_headers.get(hyper::header::CONTENT_ENCODING) {
    if !trim(content_encoding.as_bytes()).eq_ignore_ascii_case(b"identity") {
      log::debug!("content encoding not identity: {:?}", content_encoding);
      return None;
    }
  }

  let mime_compressible = match upstream_headers.get(hyper::header::CONTENT_TYPE) {
    None => false,
    Some(content_type) => {
      let bytes = content_type.as_bytes();
      content_type_matchers.iter().any(|item| item.matches(bytes))
    }
  };

  if !mime_compressible {
    log::debug!(
      "content type not mime compressible: {:?}",
      upstream_headers.get(hyper::header::CONTENT_TYPE)
    );
    return None;
  }

  let enc = select_encoding(server_encodings, request_accept_encoding);

  log::debug!("selected encoding: {:?}", enc);

  enc
}

pub fn compress_body(source: Body, enc: Compress) -> Body {
  log::debug!("compressing body with {} at level {}", enc.algo, enc.level);

  let (trail_send, trail_recv) = tokio::sync::oneshot::channel::<HeaderMap>();

  let mut trail_send = Some(trail_send);

  let input_stream = async_stream::stream! {
    tokio::pin!(source);
    while let Some(r) = source.frame().await {
      match r {
        Err(e) => {
          yield Err::<Bytes, io::Error>(io::Error::new(io::ErrorKind::Other, e));
          break;
        },

        Ok(frame) => {
          // the variant error here contains the Frame itself to reuse
          match frame.into_data() {
            Ok(buf) => yield Ok(buf),
            Err(frame) => {
              if let (Ok(trailers), Some(sender)) = (frame.into_trailers(), trail_send.take()) {
                let _ = sender.send(trailers);
              }
            }
          }
        }
      }
    }
  };

  let input_readable = tokio_util::io::StreamReader::new(input_stream);

  let level = Level::Precise(enc.level as i32);

  let encoder = match enc.algo {
    #[cfg(feature = "compression-br")]
    Encoding::Br => Encoder::brotli(input_readable, level),

    #[cfg(feature = "compression-zstd")]
    Encoding::Zstd => Encoder::zstd(input_readable, level),

    #[cfg(feature = "compression-gzip")]
    Encoding::Gzip => Encoder::gzip(input_readable, level),

    #[cfg(feature = "compression-deflate")]
    Encoding::Deflate => Encoder::deflate(input_readable, level),
  };

  let output_stream = tokio_util::io::ReaderStream::new(encoder);

  let output_frame_stream = async_stream::stream! {
    tokio::pin!(output_stream);
    while let Some(buf) = output_stream.next().await.transpose()
      .map_err(ProxyHttpError::CompressBodyChunk)? {
      yield Ok::<Frame<Bytes>, ProxyHttpError>(Frame::data(buf))
    }
    if let Ok(trailers) = trail_recv.await {
      yield Ok::<Frame<Bytes>, ProxyHttpError>(Frame::trailers(trailers))
    }
  };

  Body::stream(output_frame_stream)
}

#[cfg(test)]
mod test {

  use super::*;

  use crate::config::defaults::{
    DEFAULT_COMPRESSION, DEFAULT_COMPRESSION_CONTENT_TYPES, DEFAULT_COMPRESSION_MIN_SIZE,
  };

  macro_rules! value {
    ($value:expr) => {
      ::hyper::header::HeaderValue::try_from($value).unwrap()
    };
  }

  macro_rules! key {
    ($value:expr) => {
      ::hyper::header::HeaderName::try_from($value).unwrap()
    };
  }

  macro_rules! headers {
    ($($key:expr => $value:expr),*) => {{
      let mut headers = ::hyper::header::HeaderMap::new();
      $(
        headers.insert(key!($key), value!($value));
      )*
      headers
    }}
  }

  #[test]
  fn should_select_encodings() {
    /* (server_encodings, accept_encoding, expected) */
    let cases: &[(&[Encoding], Option<HeaderValue>, Option<Encoding>)] = &[
      // fuzz Simple, None
      #[cfg(feature = "compression-br")]
      (&[Encoding::Br], None, None),
      #[cfg(feature = "compression-zstd")]
      (&[Encoding::Zstd], None, None),
      #[cfg(feature = "compression-gzip")]
      (&[Encoding::Gzip], None, None),
      // fuzz simple indetity
      #[cfg(feature = "compression-br")]
      (&[Encoding::Br], Some(value!("identity")), None),
      #[cfg(feature = "compression-zstd")]
      (&[Encoding::Zstd], Some(value!("identity")), None),
      #[cfg(feature = "compression-gzip")]
      (&[Encoding::Gzip], Some(value!("identity")), None),
      // fuzz Simple, Some
      #[cfg(feature = "compression-br")]
      (&[Encoding::Br], Some(value!("br")), Some(Encoding::Br)),
      #[cfg(feature = "compression-zstd")]
      (
        &[Encoding::Zstd],
        Some(value!("zstd")),
        Some(Encoding::Zstd),
      ),
      #[cfg(feature = "compression-gzip")]
      (
        &[Encoding::Gzip],
        Some(value!("gzip")),
        Some(Encoding::Gzip),
      ),
      // fuzz Pair, None
      #[cfg(all(feature = "compression-br", feature = "compression-zstd"))]
      (&[Encoding::Br, Encoding::Zstd], None, None),
      #[cfg(all(feature = "compression-zstd", feature = "compression-gzip"))]
      (&[Encoding::Zstd, Encoding::Gzip], None, None),
      #[cfg(all(feature = "compression-gzip", feature = "compression-br"))]
      (&[Encoding::Gzip, Encoding::Br], None, None),
      // fizz Repeated, Self
      #[cfg(feature = "compression-br")]
      (
        &[Encoding::Br, Encoding::Br],
        Some(value!("br")),
        Some(Encoding::Br),
      ),
      #[cfg(feature = "compression-zstd")]
      (
        &[Encoding::Zstd, Encoding::Zstd],
        Some(value!("zstd")),
        Some(Encoding::Zstd),
      ),
      #[cfg(feature = "compression-gzip")]
      (
        &[Encoding::Gzip, Encoding::Gzip],
        Some(value!("gzip")),
        Some(Encoding::Gzip),
      ),
      // fuzz Pair, no match, None
      #[cfg(all(feature = "compression-br", feature = "compression-zstd"))]
      (&[Encoding::Br, Encoding::Zstd], Some(value!("gzip")), None),
      #[cfg(all(feature = "compression-zstd", feature = "compression-gzip"))]
      (&[Encoding::Zstd, Encoding::Gzip], Some(value!("br")), None),
      #[cfg(all(feature = "compression-gzip", feature = "compression-br"))]
      (&[Encoding::Gzip, Encoding::Br], Some(value!("zstd")), None),
      // fuzz Triple, empty header, None
      #[cfg(all(
        feature = "compression-br",
        feature = "compression-zstd",
        feature = "compression-gzip"
      ))]
      (
        &[Encoding::Br, Encoding::Zstd, Encoding::Gzip],
        Some(value!("")),
        None,
      ),
      #[cfg(all(
        feature = "compression-zstd",
        feature = "compression-gzip",
        feature = "compression-br"
      ))]
      (
        &[Encoding::Zstd, Encoding::Gzip, Encoding::Br],
        Some(value!(",,,,")),
        None,
      ),
      #[cfg(all(
        feature = "compression-gzip",
        feature = "compression-br",
        feature = "compression-zstd"
      ))]
      (
        &[Encoding::Gzip, Encoding::Br, Encoding::Zstd],
        Some(value!("   ")),
        None,
      ),
      // fuzz Empty, vary, None
      (&[], Some(value!("br")), None),
      (&[], Some(value!("gzip")), None),
      (&[], Some(value!("zstd")), None),
      // fuzz empty, empty, None
      (&[], Some(value!(" ")), None),
      (&[], Some(value!("     ")), None),
      (&[], Some(value!(",,,,,")), None),
      // fuzz Pair, ("zstd, "gzip", "br"),
      #[cfg(all(feature = "compression-br", feature = "compression-zstd"))]
      (
        &[Encoding::Br, Encoding::Zstd],
        Some(value!("zstd, gzip, br")),
        Some(Encoding::Br),
      ),
      #[cfg(all(feature = "compression-zstd", feature = "compression-gzip"))]
      (
        &[Encoding::Zstd, Encoding::Gzip],
        Some(value!("zstd, gzip, br")),
        Some(Encoding::Zstd),
      ),
      #[cfg(all(feature = "compression-gzip", feature = "compression-br"))]
      (
        &[Encoding::Gzip, Encoding::Br],
        Some(value!("zstd, gzip, br")),
        Some(Encoding::Gzip),
      ),
      // fuzz Pair, ("gzip, "zstd", "br"),
      #[cfg(all(feature = "compression-br", feature = "compression-gzip"))]
      (
        &[Encoding::Br, Encoding::Gzip],
        Some(value!("gzip, zstd, br")),
        Some(Encoding::Br),
      ),
      #[cfg(feature = "compression-zstd")]
      (
        &[Encoding::Zstd, Encoding::Zstd],
        Some(value!("gzip, zstd, br")),
        Some(Encoding::Zstd),
      ),
      #[cfg(feature = "compression-gzip")]
      (
        &[Encoding::Gzip, Encoding::Gzip],
        Some(value!("gzip, zstd, br")),
        Some(Encoding::Gzip),
      ),
      /* fuzz Triple, None */
      #[cfg(all(
        feature = "compression-br",
        feature = "compression-zstd",
        feature = "compression-gzip"
      ))]
      (&[Encoding::Br, Encoding::Zstd, Encoding::Gzip], None, None),
      #[cfg(all(
        feature = "compression-zstd",
        feature = "compression-gzip",
        feature = "compression-br"
      ))]
      (&[Encoding::Zstd, Encoding::Gzip, Encoding::Br], None, None),
      #[cfg(all(
        feature = "compression-gzip",
        feature = "compression-br",
        feature = "compression-zstd"
      ))]
      (&[Encoding::Gzip, Encoding::Br, Encoding::Zstd], None, None),
      /* fuzz Triple, Some */
      #[cfg(all(
        feature = "compression-br",
        feature = "compression-zstd",
        feature = "compression-gzip"
      ))]
      (
        &[Encoding::Br, Encoding::Zstd, Encoding::Gzip],
        Some(value!("br, zstd, gzip")),
        Some(Encoding::Br),
      ),
      #[cfg(all(
        feature = "compression-zstd",
        feature = "compression-gzip",
        feature = "compression-br"
      ))]
      (
        &[Encoding::Zstd, Encoding::Gzip, Encoding::Br],
        Some(value!("br, zstd, gzip")),
        Some(Encoding::Zstd),
      ),
      #[cfg(all(
        feature = "compression-gzip",
        feature = "compression-br",
        feature = "compression-zstd"
      ))]
      (
        &[Encoding::Gzip, Encoding::Br, Encoding::Zstd],
        Some(value!("br, zstd, gzip")),
        Some(Encoding::Gzip),
      ),
    ];

    // do the test
    for (i, (server_encodings, accept_encoding, expected)) in cases.iter().enumerate() {
      let server_compression = server_encodings
        .iter()
        .map(|algo| Compress {
          algo: *algo,
          level: 1,
        })
        .collect::<Vec<_>>();

      let result = select_encoding(&server_compression, accept_encoding.as_ref());
      let algo = result.map(|item| item.algo);
      assert_eq!(
        &algo, expected,
        "server_encodings #{i}: {:?}, accept_encoding: {:?}",
        server_encodings, accept_encoding
      );
    }
  }

  #[cfg(feature = "compression-gzip")]
  #[test]
  fn should_compress_with_text_plain_and_identity() {
    let headers = headers! { "content-type" => "text/plain", "content-encoding" => "identity" };
    let encoding = should_compress(
      DEFAULT_COMPRESSION,
      DEFAULT_COMPRESSION_CONTENT_TYPES,
      DEFAULT_COMPRESSION_MIN_SIZE,
      Some(&value!("gzip")),
      StatusCode::OK,
      SizeHint::with_exact(1000),
      &headers,
    );
    assert_eq!(encoding.map(|item| item.algo), Some(Encoding::Gzip));
  }

  #[cfg(feature = "compression-gzip")]
  #[test]
  fn should_compress_with_text_plain_none() {
    let headers = headers! { "content-type" => "text/plain" };
    let encoding = should_compress(
      DEFAULT_COMPRESSION,
      DEFAULT_COMPRESSION_CONTENT_TYPES,
      DEFAULT_COMPRESSION_MIN_SIZE,
      Some(&value!("gzip")),
      StatusCode::OK,
      SizeHint::with_exact(1000),
      &headers,
    );
    assert_eq!(encoding.map(|item| item.algo), Some(Encoding::Gzip));
  }
}
