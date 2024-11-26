mod common;
use axum::{body::Body, response::Response};
use clap::Parser;
use common::{block_on, dir};
use http::{header::CONNECTION, HeaderValue};
use proxide::cli::{self, args::Args};
use reqwest::ClientBuilder;

#[test]
fn reload() {
  block_on(async move {
    let dir = dir();

    let cfg_path = dir.file("config.yml");
    let pidfile = dir.file("proxide.pid");

    let stream_port_1 = 25101;
    let http_port_1 = 25201;

    let stream_port_2 = 25102;
    let http_port_2 = 25202;

    let config_src = include_str!("reload.yml");

    let config_1 = config_src
      .replace("%PIDFILE%", &pidfile)
      .replace("%STREAM_PORT%", &stream_port_1.to_string())
      .replace("%HTTP_PORT%", &http_port_1.to_string());

    std::fs::write(&cfg_path, &config_1).unwrap();

    let h_stream_1 = || async {
      let mut res = Response::new(Body::empty());
      res
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
      res
        .headers_mut()
        .insert("x-backend", HeaderValue::from_static("stream-1"));
      res
        .headers_mut()
        .insert("x-test", HeaderValue::from_static("reload"));
      res
    };

    let h_http_1 = || async {
      let mut res = Response::new(Body::empty());
      // res
      //   .headers_mut()
      //   .insert(CONNECTION, HeaderValue::from_static("close"));
      res
        .headers_mut()
        .insert("x-backend", HeaderValue::from_static("http-1"));
      res
        .headers_mut()
        .insert("x-test", HeaderValue::from_static("reload"));
      res
    };

    let h_stream_2 = || async {
      let mut res = Response::new(Body::empty());
      res
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
      res
        .headers_mut()
        .insert("x-backend", HeaderValue::from_static("stream-2"));
      res
        .headers_mut()
        .insert("x-test", HeaderValue::from_static("reload"));
      res
    };

    let h_http_2 = || async {
      let mut res = Response::new(Body::empty());
      // res
      //   .headers_mut()
      //   .insert(CONNECTION, HeaderValue::from_static("close"));
      res
        .headers_mut()
        .insert("x-backend", HeaderValue::from_static("http-2"));
      res
        .headers_mut()
        .insert("x-test", HeaderValue::from_static("reload"));
      res
    };

    let server_stream_1 = axum::Router::new().route("/", axum::routing::get(h_stream_1));
    let server_http_1 = axum::Router::new().route("/", axum::routing::get(h_http_1));
    let server_stream_2 = axum::Router::new().route("/", axum::routing::get(h_stream_2));
    let server_http_2 = axum::Router::new().route("/", axum::routing::get(h_http_2));

    tokio::spawn(async move {
      let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{stream_port_1}"))
        .await
        .unwrap();
      axum::serve(listener, server_stream_1).await.unwrap();
    });

    tokio::spawn(async move {
      let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{http_port_1}"))
        .await
        .unwrap();
      axum::serve(listener, server_http_1).await.unwrap();
    });

    tokio::spawn(async move {
      let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{stream_port_2}"))
        .await
        .unwrap();
      axum::serve(listener, server_stream_2).await.unwrap();
    });

    tokio::spawn(async move {
      let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{http_port_2}"))
        .await
        .unwrap();
      axum::serve(listener, server_http_2).await.unwrap();
    });

    let args = Args::try_parse_from(["proxide", "start", "--config", &cfg_path]).unwrap();
    std::thread::spawn(move || {
      cli::run(args).unwrap();
    });

    let client = ClientBuilder::new()
      .danger_accept_invalid_certs(true)
      .build()
      .unwrap();

    for i in 0..1500 {
      let (scheme, port, backend) = match i % 3 {
        0 => ("http", 25200, "http-1"),
        1 => ("https", 25443, "http-1"),
        _ => ("http", 25100, "stream-1"),
      };
      let res = client
        .get(&format!("{scheme}://127.0.0.1:{port}"))
        .send()
        .await
        .unwrap();
      assert_header!(res, "x-test", "reload");
      assert_header!(res, "x-backend", backend);
    }

    let new_config = config_src
      .replace("%PIDFILE%", &pidfile)
      .replace("%STREAM_PORT%", &stream_port_2.to_string())
      .replace("%HTTP_PORT%", &http_port_2.to_string());
    std::fs::write(&cfg_path, &new_config).unwrap();

    let args = Args::try_parse_from([
      "proxide", "signal", "--config", &cfg_path, "--signal", "reload",
    ])
    .unwrap();
    cli::run(args).unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    for i in 0..1500 {
      let (scheme, port, backend) = match i % 3 {
        0 => ("http", 25200, "http-2"),
        1 => ("https", 25443, "http-2"),
        _ => ("http", 25100, "stream-2"),
      };
      let res = client
        .get(&format!("{scheme}://127.0.0.1:{port}"))
        .send()
        .await
        .unwrap();
      assert_header!(res, "x-test", "reload");
      assert_header!(res, "x-backend", backend);
    }
  })
}
