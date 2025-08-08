mod common;

use common::block_on;
use http::{HeaderName, HeaderValue, Version};
use http_body_util::BodyExt;
use hyper::{body::Incoming, service};
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxide::body::Body;
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpListener;

use crate::common::request;

#[test]
fn request_body() {
  crate::lock!("request-body.yml");

  block_on(async move {
    let size = 1_000_000;

    let body = vec![0u8; size];

    let listener = TcpListener::bind("0.0.0.0:23850").await.unwrap();

    tokio::spawn(async move {
      loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
          let io = TokioIo::new(socket);
          let http =
            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).http1_only();

          let service = service::service_fn(|req: hyper::Request<Incoming>| async move {
            let method = req.method().to_string();
            let body = req.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body, vec![0; size]);
            let mut res = hyper::Response::new(Body::empty());
            *res.status_mut() = hyper::StatusCode::OK;
            res.headers_mut().insert(
              HeaderName::from_static("x-method"),
              HeaderValue::from_str(&method).unwrap(),
            );
            res.headers_mut().insert(
              HeaderName::from_static("x-test"),
              HeaderValue::from_static("request-body"),
            );
            Ok::<_, Infallible>(res)
          });

          http.serve_connection(io, service).await.unwrap();
        });
      }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let variants = [
      (Version::HTTP_10, "http", 23800),
      (Version::HTTP_11, "http", 23800),
      (Version::HTTP_2, "http", 23800),
      (Version::HTTP_10, "https", 23801),
      (Version::HTTP_11, "https", 23801),
      (Version::HTTP_2, "https", 23801),
      (Version::HTTP_3, "https", 23802),
    ];

    for (version, scheme, port) in variants {
      for method in &["POST", "PUT", "PATCH"] {
        log::info!("testing {version:?} {method} {scheme} {port}");
        let mut req = reqwest::Request::new(
          method.parse().unwrap(),
          format!("{scheme}://127.0.0.1:{port}/").parse().unwrap(),
        );
        *req.version_mut() = version;
        *req.body_mut() = Some(body.clone().into());

        let res = request(req).await.unwrap();

        assert_status!(res, OK);
        assert_header!(res, "x-test", "request-body");
        assert_header!(res, "x-method", method);
      }
    }
  })
}
