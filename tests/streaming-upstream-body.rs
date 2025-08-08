use bytes::Bytes;
use http::Version;
use reqwest::Request;
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpListener;

use crate::common::{block_on, request};

mod common;

#[test]
fn streaming_upstream_body() {
  launch!("streaming-upstream-body.yml");

  block_on(async move {
    tokio::spawn(async move {
      let upstream = axum::Router::<()>::new().route("/", axum::routing::get(streaming_body));
      let listener = TcpListener::bind("0.0.0.0:23950").await.unwrap();
      axum::serve(listener, upstream.into_make_service())
        .await
        .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(20)).await;

    let variants = [
      (Version::HTTP_10, "http", 23900),
      (Version::HTTP_11, "http", 23900),
      (Version::HTTP_2, "http", 23900),
      (Version::HTTP_10, "https", 23901),
      (Version::HTTP_11, "https", 23901),
      (Version::HTTP_2, "https", 23901),
      (Version::HTTP_3, "https", 23902),
    ];

    for (version, scheme, port) in variants {
      log::info!("testing {version:?} {scheme} {port}");
      let uri = format!("{scheme}://127.0.0.1:{port}/");
      let mut req = Request::new("GET".parse().unwrap(), uri.parse().unwrap());
      *req.version_mut() = version;
      let res = request(req).await.unwrap();
      assert_status!(res, 200);
      assert_header!(res, "content-type", "text/plain");
      assert_body!(res, "a".repeat(10_000));
    }
  });
}

async fn streaming_body() -> impl axum::response::IntoResponse {
  let body = axum::body::Body::from_stream(async_stream::stream! {
    for _ in 0..10 {
      tokio::time::sleep(Duration::from_millis(10)).await;
      yield Ok::<_, Infallible>(Bytes::from(vec![b'a'; 1_000]));
    }
  });

  axum::response::Response::builder()
    .header("content-type", "text/plain")
    .body(body)
    .unwrap()
}
