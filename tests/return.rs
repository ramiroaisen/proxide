mod common;
use common::{block_on, get};
use http::Version;
use reqwest::Request;

use crate::common::request;

const VARIANTS: &[(Version, &str, u16)] = &[
  (Version::HTTP_10, "http", 20200),
  (Version::HTTP_11, "http", 20200),
  (Version::HTTP_2, "http", 20200),
  (Version::HTTP_10, "https", 20201),
  (Version::HTTP_11, "https", 20201),
  (Version::HTTP_2, "https", 20201),
  // TODO: h3 (Version::HTTP_3, "https", 20202),
];

#[test]
fn return_200() {
  crate::lock!("return.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      let mut req = Request::new(
        http::Method::GET,
        format!("{scheme}://127.0.0.1:{port}/return-200")
          .parse()
          .unwrap(),
      );
      *req.version_mut() = *version;
      let res = request(req).await.unwrap();
      assert_status!(res, OK);
      assert_header!(res, "content-type", "text/plain");
    }

    let res = get("http://127.0.0.1:20200/return-200")
      .await
      .expect("error making request (return 200)");
    assert_status!(res, OK);
    assert_header!(res, "content-type", "text/plain");
  });
}

#[test]
fn return_301() {
  crate::lock!("return.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      let mut req = Request::new(
        http::Method::GET,
        format!("{scheme}://127.0.0.1:{port}/return-301")
          .parse()
          .unwrap(),
      );
      *req.version_mut() = *version;
      let res = request(req).await.unwrap();
      assert_status!(res, MOVED_PERMANENTLY);
      assert_header!(res, "location", "https://example.com");
    }
  })
}

#[test]
fn return_body() {
  crate::lock!("return.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      let mut req = Request::new(
        http::Method::GET,
        format!("{scheme}://127.0.0.1:{port}/return-body")
          .parse()
          .unwrap(),
      );
      *req.version_mut() = *version;
      let res = request(req).await.unwrap();
      assert_status!(res, OK);
      assert_header!(res, hyper::header::CONTENT_TYPE, "text/plain");
      assert_body!(res, "example test body");
    }
  })
}

#[test]
fn return_vars() {
  crate::lock!("return.yml");
  block_on(async move {
    for (version, scheme, port) in VARIANTS {
      let mut req = Request::new(
        http::Method::GET,
        format!("{scheme}://127.0.0.1:{port}/return-vars")
          .parse()
          .unwrap(),
      );
      *req.version_mut() = *version;
      let res = request(req).await.unwrap();

      assert_status!(res, OK);
      assert_header!(res, "content-type", "text/plain");

      assert_header!(res, "x-method", "GET");
      assert_header!(res, "x-scheme", scheme);
      assert_header!(res, "x-host", "127.0.0.1");
      assert_header!(res, "x-port", &format!(":{port}"));
      assert_header!(res, "x-request-uri", "/return-vars");
      assert_header!(res, "x-remote-ip", "127.0.0.1");

      assert_body!(
        res,
        format!("GET {scheme}://127.0.0.1:{port}/return-vars from 127.0.0.1")
      );
    }
  })
}
