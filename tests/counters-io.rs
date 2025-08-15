#![cfg(feature = "stats")]

use common::https_request;
use http::HeaderName;
use http::HeaderValue;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxide::config::Config;
use proxide::tls::{load_certs, load_private_key};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::{sync::atomic::Ordering, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
trait Io: AsyncRead + AsyncWrite + Send + Sync {}

impl<T: AsyncRead + AsyncWrite + Send + Sync> Io for T {}

mod common;

#[ignore]
#[test]
fn counters_io() {
  for port in [0, 1, 2, 3] {
    eprintln!("iter: {port}");
    let config_str = include_str!("counters-io.yml");
    let config: Config = serde_yml::from_str(config_str).expect("error parsing yaml config file");

    let ssl = match port {
      0 | 2 => false,
      1 | 3 => true,
      _ => unreachable!(),
    };

    let (read_counter, write_counter) = match port {
      0 | 1 => {
        let upstream = match &config.http.apps[port].handle {
          proxide::config::HttpHandle::Proxy { upstream, .. } => &upstream[0],
          _ => unreachable!(),
        };
        (
          upstream.stats_total_read_bytes.clone(),
          upstream.stats_total_write_bytes.clone(),
        )
      }
      2 | 3 => {
        let upstream = match &config.stream.apps[port - 2].handle {
          proxide::config::StreamHandle::Proxy { upstream, .. } => &upstream[0],
        };
        (
          upstream.stats_total_read_bytes.clone(),
          upstream.stats_total_write_bytes.clone(),
        )
      }
      _ => unreachable!(),
    };

    launch!(@parsed config);

    common::block_on(async move {
      let max_extra_data_per_connection: usize = 10_000;
      let data_per_connection: usize = 5_000_000;
      let body = vec![0u8; data_per_connection];

      let server = TcpListener::bind(format!("127.0.0.1:1025{port}"))
        .await
        .unwrap();

      tokio::spawn(async move {
        loop {
          let (stream, _) = server.accept().await.unwrap();

          tokio::spawn(async move {
            let mut stream = Box::pin(stream) as Pin<Box<dyn Io>>;

            if ssl {
              let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                  load_certs("cert/self-signed.pem").unwrap(),
                  load_private_key("cert/self-signed.pem").unwrap(),
                )
                .unwrap();

              let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

              let aux = acceptor.accept(stream).await.unwrap();

              stream = Box::pin(aux);
            }

            let io = TokioIo::new(stream);

            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(
              io,
              service_fn(|req: hyper::Request<Incoming>| async move {
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                let mut res = hyper::Response::new(proxide::body::Body::full(bytes));
                *res.status_mut() = hyper::StatusCode::OK;
                res.headers_mut().insert(
                  HeaderName::from_static("x-test"),
                  HeaderValue::from_static("counters-io"),
                );
                Ok::<_, Infallible>(res)
              }),
            );
          });
        }
      });

      tokio::time::sleep(Duration::from_millis(100)).await;

      let scheme = if ssl { "https" } else { "http" };

      let mut req = reqwest::Request::new(
        reqwest::Method::POST,
        format!("{scheme}://127.0.0.1:1020{port}/").parse().unwrap(),
      );

      *req.body_mut() = Some(reqwest::Body::from(body));

      let res = https_request(req).await.unwrap();
      assert_status!(res, 200);
      assert_header!(res, "x-test", "counters-io");

      tokio::time::sleep(Duration::from_millis(100)).await;

      let read = read_counter.load(Ordering::Relaxed) as usize;
      let write = write_counter.load(Ordering::Relaxed) as usize;

      let min = data_per_connection;
      let max = data_per_connection + max_extra_data_per_connection;

      dbg!(read, write, min, max);

      assert!(read >= min && read <= max);
      assert!(write >= min && write <= max);
    });
  }
}
