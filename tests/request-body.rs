mod common;

use common::{block_on, send};
use http::{HeaderName, HeaderValue};
use http_body_util::BodyExt;
use hyper::{body::Incoming, http::Method, service};
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxide::body::Body;
use std::{convert::Infallible, str::FromStr, time::Duration};
use tokio::net::TcpListener;

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

    for method in &["POST", "PUT", "PATCH"] {
      let request = hyper::Request::builder()
        .method(Method::from_str(method).unwrap())
        .uri("http://127.0.0.1:23800/")
        .body(Body::full(body.clone()))
        .unwrap();

      let res = send(request).await.unwrap();
      let (parts, incoming) = res.into_parts();
      let res = hyper::Response::from_parts(parts, Body::empty());

      use http_body_util::BodyExt;
      dbg!(method);
      let bytes = incoming.collect().await.unwrap().to_bytes();
      let body = String::from_utf8_lossy(bytes.as_ref());
      dbg!(body);

      assert_status!(res, OK);
      assert_header!(res, "x-test", "request-body");
      assert_header!(res, "x-method", method);
    }
  })
}
