mod common;
use common::block_on;
use http::{HeaderValue, Version};
use reqwest::Request;

use crate::common::request;

const VARIANTS: &[(Version, &str, u16)] = &[
  (Version::HTTP_10, "http", 20100),
  (Version::HTTP_11, "http", 20100),
  (Version::HTTP_2, "http", 20100),
  (Version::HTTP_10, "https", 20101),
  (Version::HTTP_11, "https", 20101),
  (Version::HTTP_2, "https", 20101),
  // TODO: h3 (Version::HTTP_3, "https", 20102),
];

#[test]
fn compression_client_select() {
  crate::lock!("compression.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      for encoding in ["gzip", "br", "zstd", "deflate"] {
        let mut req = Request::new(
          http::Method::GET,
          format!("{scheme}://127.0.0.1:{port}/compression-all")
            .parse()
            .unwrap(),
        );
        *req.version_mut() = *version;
        req.headers_mut().insert(
          hyper::header::ACCEPT_ENCODING,
          HeaderValue::from_static(encoding),
        );

        let res = request(req).await.unwrap();

        assert_status!(res, OK);
        assert_header!(res, hyper::header::CONTENT_ENCODING, encoding);
      }
    }
  })
}

#[test]
fn compression_ignore_on_octet_stream() {
  crate::lock!("compression.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      for encoding in ["gzip", "br", "zstd", "deflate"] {
        let mut req = Request::new(
          http::Method::GET,
          format!("{scheme}://127.0.0.1:{port}/compression-all-octet-stream")
            .parse()
            .unwrap(),
        );
        *req.version_mut() = *version;
        req.headers_mut().insert(
          hyper::header::ACCEPT_ENCODING,
          HeaderValue::from_static(encoding),
        );

        let res = request(req).await.unwrap();

        assert_status!(res, OK);
        let header = res.headers().get(hyper::header::CONTENT_ENCODING);
        assert!(header.is_none() || header.unwrap() == "identity");
      }
    }
  });
}

#[test]
fn compression_server_select() {
  crate::lock!("compression.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      for encoding in ["gzip", "br", "zstd", "deflate"] {
        let mut req = Request::new(
          http::Method::GET,
          format!("{scheme}://127.0.0.1:{port}/compression-{encoding}")
            .parse()
            .unwrap(),
        );
        *req.version_mut() = *version;
        req.headers_mut().insert(
          hyper::header::ACCEPT_ENCODING,
          HeaderValue::from_static("gzip,br,zstd,deflate"),
        );

        let res = request(req).await.unwrap();

        assert_status!(res, OK);
        assert_header!(res, hyper::header::CONTENT_ENCODING, encoding);
      }
    }
  })
}
