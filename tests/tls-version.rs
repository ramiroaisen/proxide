use http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Version};
use http::{Request, Response};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxide::body::Body;
use proxide::tls::danger_no_cert_verifier::DangerNoCertVerifier;
use std::{convert::Infallible, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod common;
use common::block_on;

#[test]
fn tls_version() {
  launch!("tls-version.yml");

  for port in [0, 1] {
    for client_version in [2, 3] {
      for server_version in [2, 3] {
        for http_version in [1, 2] {
          dbg!(port, client_version, server_version, http_version);

          block_on(async move {
            let listener = TcpListener::bind(&format!("127.0.0.1:1455{port}"))
              .await
              .unwrap();

            dbg!(listener.local_addr().unwrap());

            let server_version = match server_version {
              2 => &rustls::version::TLS12,
              3 => &rustls::version::TLS13,
              _ => unreachable!(),
            };

            let mut config =
              rustls::ServerConfig::builder_with_protocol_versions(&[server_version])
                .with_no_client_auth()
                .with_single_cert(
                  proxide::tls::load_certs("cert/self-signed-cert.pem").unwrap(),
                  proxide::tls::load_private_key("cert/self-signed-key.pem").unwrap(),
                )
                .unwrap();

            match http_version {
              1 => config.alpn_protocols.push(b"http/1.1".to_vec()),
              2 => config.alpn_protocols.push(b"h2".to_vec()),
              _ => unreachable!(),
            };

            dbg!(server_version, &config, http_version);

            let acceptor = TlsAcceptor::from(Arc::new(config));

            let server = async move {
              let (stream, _) = listener.accept().await.unwrap();
              let tls_stream = acceptor.accept(stream).await.unwrap();

              let service = service_fn(|_: Request<Incoming>| async move {
                let mut res = Response::new(Body::empty());
                res
                  .headers_mut()
                  .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                res.headers_mut().insert(
                  HeaderName::from_static("x-test"),
                  HeaderValue::from_static("tls-version"),
                );
                Ok::<_, Infallible>(res)
              });

              match http_version {
                1 => hyper::server::conn::http1::Builder::new()
                  .serve_connection(TokioIo::new(tls_stream), service)
                  .await
                  .unwrap(),
                2 => hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                  .serve_connection(TokioIo::new(tls_stream), service)
                  .await
                  .unwrap(),
                _ => unreachable!(),
              }
            };

            let client = async move {
              let client_version = match client_version {
                2 => &rustls::version::TLS12,
                3 => &rustls::version::TLS13,
                _ => unreachable!(),
              };

              let path = match http_version {
                1 => "/h1",
                2 => "/h2",
                _ => unreachable!(),
              };

              let h_version = match http_version {
                1 => Version::HTTP_11,
                2 => Version::HTTP_2,
                _ => unreachable!(),
              };

              let addr: std::net::SocketAddr = format!("127.0.0.1:1450{port}").parse().unwrap();

              let tcp = TcpStream::connect(&addr).await.unwrap();

              let mut config =
                rustls::ClientConfig::builder_with_protocol_versions(&[client_version])
                  .dangerous()
                  .with_custom_certificate_verifier(Arc::new(DangerNoCertVerifier))
                  .with_no_client_auth();

              match http_version {
                1 => config.alpn_protocols.push(b"http/1.1".to_vec()),
                2 => config.alpn_protocols.push(b"h2".to_vec()),
                _ => unreachable!(),
              };

              dbg!(addr, client_version, path, h_version, &config,);

              let connector = TlsConnector::from(Arc::new(config));

              let tls = connector
                .connect("example.com".try_into().unwrap(), tcp)
                .await
                .unwrap();

              let request = hyper::Request::builder()
                .version(h_version)
                .method("GET")
                .uri(format!("https://127.0.0.1:145{port}{path}"))
                .header("host", "example.com")
                .body(Body::empty())
                .unwrap();

              let res = match http_version {
                1 => {
                  let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                    .await
                    .unwrap();

                  tokio::spawn(conn);
                  send.send_request(request).await.unwrap()
                }

                2 => {
                  let (mut send, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                      .await
                      .unwrap();

                  tokio::spawn(conn);
                  send.send_request(request).await.unwrap()
                }

                _ => unreachable!(),
              };

              assert_status!(res, OK);
              assert_header!(res, "x-test", "tls-version");
            };

            tokio::spawn(server);
            client.await;
          });
        }
      }
    }
  }
}
